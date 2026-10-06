'use strict';
/* Vercel serverless entry: every /api/* request is handled by the Express app.
   Static files (public/) are served by Vercel's CDN; the SPA uses hash routing,
   so the server only ever serves / and /api/*. */
module.exports = require('../server');
