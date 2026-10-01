// Cloudflare Pages Function: every /api/* request goes to the Aegisly router.
import { handleApi } from '../../src/api.js';

export const onRequest = (context) => handleApi(context.request, context.env);
