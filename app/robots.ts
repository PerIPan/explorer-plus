import type { MetadataRoute } from 'next';

// AI answer-engine / search crawlers we explicitly welcome (GEO). Same content
// access as everyone else; /api/ and /search stay out of the index.
const AI_CRAWLERS = [
  'GPTBot', 'OAI-SearchBot', 'ChatGPT-User',        // OpenAI
  'ClaudeBot', 'Claude-SearchBot', 'anthropic-ai',  // Anthropic
  'PerplexityBot', 'Perplexity-User',               // Perplexity
  'Google-Extended',                                // Google AI / Gemini
  'Applebot-Extended',                              // Apple Intelligence
  'CCBot',                                          // Common Crawl (feeds many LLMs)
];

export default function robots(): MetadataRoute.Robots {
  const disallow = ['/api/', '/search'];
  return {
    rules: [
      { userAgent: '*', allow: '/', disallow },
      ...AI_CRAWLERS.map((userAgent) => ({ userAgent, allow: '/', disallow })),
    ],
    sitemap: 'https://mitre-explorer.org/sitemap.xml',
  };
}
