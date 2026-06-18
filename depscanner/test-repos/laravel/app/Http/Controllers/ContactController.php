<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use PHPMailer\PHPMailer\PHPMailer;

class ContactController extends Controller
{
    public function send(Request $request)
    {
        // REACHABLE: command_injection (dep CVE) — user-supplied sender
        // address flows into PHPMailer::setFrom, which interpolates it into
        // mail()'s sendmail -f option (CVE-2016-10033, phpmailer 5.2.16).
        $email = $request->input('email');

        $mail = new PHPMailer(true);
        $mail->setFrom($email, 'Contact Form');
        $mail->addAddress('support@example.com');
        $mail->Subject = 'New contact-form message';
        $mail->Body = $request->input('message');
        $mail->send();

        return response()->json(['ok' => true]);
    }
}
