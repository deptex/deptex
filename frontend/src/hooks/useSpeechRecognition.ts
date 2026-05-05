import { useCallback, useEffect, useRef, useState } from 'react';

// Thin wrapper around the Web Speech API. Streams finalised transcript chunks
// through `onAppend` so callers can splice them into a textarea (or whatever
// state they own) live as the user speaks. Interim (non-finalised) text is
// surfaced separately for an optional "ghost text" UI.
//
// Browser support: Chrome, Edge, Safari (macOS + iOS 14.5+). Firefox does NOT
// implement SpeechRecognition — `supported` will be false there and callers
// should fall back to a hidden mic / typed-only UX.

interface UseSpeechRecognitionOptions {
  // Called with each finalised chunk. Append to your value, optionally
  // prefixing with a space if the existing value isn't empty.
  onAppend: (text: string) => void;
  // BCP-47 language tag. Defaults to the browser locale.
  lang?: string;
  // Called when recognition ends for any reason (manual stop, silence
  // timeout, error). Useful for cleanup state.
  onEnd?: () => void;
  // Called on permission-denied / network / aborted errors. Strings are the
  // raw `event.error` codes from the SpeechRecognitionErrorEvent.
  onError?: (code: string) => void;
}

interface UseSpeechRecognitionResult {
  supported: boolean;
  listening: boolean;
  // Live (non-finalised) transcript. Resets between recognition sessions.
  interim: string;
  start: () => void;
  stop: () => void;
  toggle: () => void;
}

export function useSpeechRecognition(opts: UseSpeechRecognitionOptions): UseSpeechRecognitionResult {
  const [listening, setListening] = useState(false);
  const [interim, setInterim] = useState('');
  const recognitionRef = useRef<any>(null);
  // Refs so the start/stop closures stay stable while still seeing the latest
  // callbacks the parent passes in.
  const optsRef = useRef(opts);
  useEffect(() => { optsRef.current = opts; });

  const SpeechRecognitionCtor =
    typeof window !== 'undefined'
      ? ((window as any).SpeechRecognition || (window as any).webkitSpeechRecognition)
      : null;
  const supported = !!SpeechRecognitionCtor;

  const stop = useCallback(() => {
    const rec = recognitionRef.current;
    if (!rec) return;
    try { rec.stop(); } catch { /* already stopped */ }
  }, []);

  const start = useCallback(() => {
    if (!supported || recognitionRef.current) return;
    const recognition = new SpeechRecognitionCtor();
    recognition.continuous = true;
    recognition.interimResults = true;
    recognition.lang = optsRef.current.lang || (typeof navigator !== 'undefined' ? navigator.language : 'en-US');

    recognition.onresult = (event: any) => {
      let interimChunk = '';
      for (let i = event.resultIndex; i < event.results.length; i++) {
        const r = event.results[i];
        const text: string = r[0].transcript;
        if (r.isFinal) {
          optsRef.current.onAppend(text.trim());
        } else {
          interimChunk += text;
        }
      }
      setInterim(interimChunk);
    };

    recognition.onerror = (e: any) => {
      optsRef.current.onError?.(String(e?.error ?? 'unknown'));
    };

    recognition.onend = () => {
      setListening(false);
      setInterim('');
      recognitionRef.current = null;
      optsRef.current.onEnd?.();
    };

    try {
      recognition.start();
      recognitionRef.current = recognition;
      setListening(true);
    } catch (err) {
      // Common cause: start() called twice in quick succession before onend
      // had a chance to fire. Drop the new attempt rather than crashing.
      console.warn('[speech] start failed', err);
      recognitionRef.current = null;
    }
  }, [supported, SpeechRecognitionCtor]);

  const toggle = useCallback(() => {
    if (recognitionRef.current) stop();
    else start();
  }, [start, stop]);

  // Stop recognition if the component unmounts mid-session — otherwise the
  // browser keeps the mic indicator on after navigation.
  useEffect(() => () => stop(), [stop]);

  return { supported, listening, interim, start, stop, toggle };
}
