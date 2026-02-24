import OpenAI from 'openai';
import { getSystemPrompt } from './systemPrompt';
import { getActionHandler, getActionDefinitionsForOpenAI, ActionResult } from './actions';
import { supabase } from '../supabase';
import { getOpenAIClient } from '../openai';


export interface ExecutionContext {
  organizationId: string;
  userId: string;
  organizationName: string;
  threadId?: string;
}

export interface ExecutionResult {
  type: 'action' | 'conversation';
  action?: string;
  parameters?: any;
  message: string; // Always include a message (natural language response)
  result?: ActionResult;
}

/**
 * Execute a user message through Aegis
 */
export async function executeMessage(
  message: string,
  context: ExecutionContext,
  conversationHistory?: Array<{ role: 'user' | 'assistant'; content: string }>
): Promise<ExecutionResult> {
  try {
    // Get system prompt
    const systemPrompt = getSystemPrompt(context.organizationName);

    // Build messages array
    const messages: OpenAI.Chat.Completions.ChatCompletionMessageParam[] = [
      { role: 'system', content: systemPrompt },
    ];

    // Add conversation history if provided
    if (conversationHistory) {
      conversationHistory.forEach(msg => {
        messages.push({
          role: msg.role,
          content: msg.content,
        });
      });
    }

    // Add current user message
    messages.push({
      role: 'user',
      content: message,
    });

    // Get action definitions for function calling
    const functions = getActionDefinitionsForOpenAI();

    // Call OpenAI
    const openai = getOpenAIClient();

    // Get model from environment variable, with fallback
    // Default to gpt-4-turbo-preview which is more accessible than gpt-4
    const model = process.env.OPENAI_MODEL || 'gpt-4-turbo-preview';

    // Validate functions format
    if (functions.length > 0) {
      // Ensure all functions have the correct structure
      const validFunctions = functions.filter(fn =>
        fn &&
        fn.type === 'function' &&
        fn.function &&
        fn.function.name
      );

      if (validFunctions.length === 0 && functions.length > 0) {
        console.error('Invalid function definitions:', JSON.stringify(functions, null, 2));
        throw new Error('Function definitions are invalid');
      }

      // Use valid functions
      functions.length = 0;
      functions.push(...validFunctions);
    }

    const completionParams: any = {
      model: model,
      messages,
    };

    // Don't set temperature - let OpenAI use the default
    // Some models (like gpt-4-turbo-preview) only support the default temperature value

    // Use tools API (newer format) - works with gpt-4-turbo-preview and newer models
    // Fall back to functions API for older models if needed
    if (functions.length > 0) {
      // Check if model supports tools (newer API)
      const supportsTools = model.includes('gpt-4') || model.includes('gpt-3.5-turbo');
      if (supportsTools) {
        completionParams.tools = functions;
        completionParams.tool_choice = 'auto';
      } else {
        // Legacy functions API
        completionParams.functions = functions.map(f => f.function);
        completionParams.function_call = 'auto';
      }
    }

    const completion = await openai.chat.completions.create(completionParams);

    const response = completion.choices[0]?.message;

    if (!response) {
      throw new Error('No response from OpenAI');
    }

    // Check if it's a tool/function call (newer API uses tool_calls, older uses function_call)
    const toolCall = response.tool_calls?.[0] || response.function_call;

    if (toolCall) {
      const fn = 'function' in toolCall && toolCall.function ? toolCall.function : { name: (toolCall as { name?: string }).name, arguments: (toolCall as { arguments?: string }).arguments };
      const functionName = fn?.name ?? '';
      const functionParams = JSON.parse(fn?.arguments || '{}');

      // Get action handler
      const handler = getActionHandler(functionName);
      if (!handler) {
        return {
          type: 'conversation',
          message: `I don't know how to perform the action "${functionName}". Please contact support.`,
        };
      }

      // Execute action
      const actionContext = {
        organizationId: context.organizationId,
        userId: context.userId,
      };

      const actionResult = await handler(functionParams, actionContext);

      // Log the action
      await logAegisActivity({
        organizationId: context.organizationId,
        requestText: message,
        actionPerformed: functionName,
        resultJson: actionResult,
      });

      // After performing an action, we need to generate a natural language response
      // Add the function result to the conversation and ask OpenAI to format a response
      const toolCallId = ('id' in toolCall && toolCall.id) || ('call_' + Date.now());

      const actionResultMessage = {
        role: 'assistant' as const,
        content: null,
        tool_calls: [{
          id: toolCallId,
          type: 'function' as const,
          function: {
            name: functionName,
            arguments: JSON.stringify(functionParams),
          },
        }],
      };

      const functionResultMessage = {
        role: 'tool' as const,
        content: JSON.stringify(actionResult),
        tool_call_id: toolCallId,
      };

      // Add the function call and result to messages, then get a natural language response
      const updatedMessages = [
        ...messages,
        actionResultMessage,
        functionResultMessage,
      ];

      // Get a natural language response from OpenAI based on the action result
      const followUpCompletion = await openai.chat.completions.create({
        model: model,
        messages: updatedMessages,
        tools: functions.length > 0 ? functions : undefined,
        tool_choice: 'none', // Don't call more functions, just respond
      });

      const followUpResponse = followUpCompletion.choices[0]?.message;
      const naturalLanguageResponse = followUpResponse?.content ||
        `I've performed the ${functionName} action. ${actionResult.success ? 'The operation completed successfully.' : 'The operation encountered an error.'}`;

      return {
        type: 'action',
        action: functionName,
        parameters: functionParams,
        result: actionResult,
        message: naturalLanguageResponse, // Add the natural language response
      };
    }

    // It's a conversation response
    const assistantMessage = response.content || 'I apologize, but I could not generate a response.';

    return {
      type: 'conversation',
      message: assistantMessage,
    };
  } catch (error: any) {
    console.error('Error executing Aegis message:', error);

    // Log the error
    await logAegisActivity({
      organizationId: context.organizationId,
      requestText: message,
      actionPerformed: 'error',
      resultJson: { error: error.message || 'Unknown error' },
    });

    return {
      type: 'conversation',
      message: 'I encountered an error processing your request. Please try again or contact support if the issue persists.',
    };
  }
}

/**
 * Log Aegis activity
 */
async function logAegisActivity(params: {
  organizationId: string;
  requestText: string;
  actionPerformed: string;
  resultJson: any;
}): Promise<void> {
  try {
    await supabase
      .from('aegis_activity_logs')
      .insert({
        organization_id: params.organizationId,
        request_text: params.requestText,
        action_performed: params.actionPerformed,
        result_json: params.resultJson,
      });
  } catch (error) {
    console.error('Error logging Aegis activity:', error);
    // Don't throw - logging is non-critical
  }
}

