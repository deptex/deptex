import { Controller, Get } from '@nestjs/common';
import * as qs from 'qs';

@Controller()
export class AppController {
  // qs is imported but only the constant `qs.formats` is referenced —
  // not the vulnerable `qs.parse` API. CVE-2022-24999 sink unreachable.
  @Get('/formats')
  formats() {
    return Object.keys(qs.formats);
  }
}
