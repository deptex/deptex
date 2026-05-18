import { Controller, Get, Query } from '@nestjs/common';
import * as qs from 'qs';

@Controller()
export class AppController {
  // CVE-2022-24999 — qs <= 6.5.2 prototype-pollution / DoS
  // when parsing crafted query strings.
  @Get('/parse')
  parse(@Query('q') q: string) {
    // Sink: qs.parse on user-controlled string.
    return qs.parse(q);
  }
}
