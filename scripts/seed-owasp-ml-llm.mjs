import pg from 'pg';
const { Pool } = pg;

const connectionString = process.env.DATABASE_URL;
if (!connectionString) { console.error('DATABASE_URL required'); process.exit(1); }

const isProduction = connectionString.includes('neon') || connectionString.includes('vercel');
const pool = new Pool({
  connectionString,
  max: 1,
  ssl: isProduction ? { rejectUnauthorized: true } : undefined,
});

const ML_TOP10 = [
  { id: 'ML01', name: 'Input Manipulation Attack', desc: 'Adversarial inputs cause model to produce incorrect predictions.', url: 'https://mltop10.info/', atlas: ['AML.T0043'], cwes: ['CWE-20'], draft: true },
  { id: 'ML02', name: 'Data Poisoning Attack', desc: 'Attacker injects malicious data into training set to corrupt model behavior.', url: 'https://mltop10.info/', atlas: ['AML.T0020'], cwes: ['CWE-506'], draft: true },
  { id: 'ML03', name: 'Model Inversion Attack', desc: 'Attacker reconstructs sensitive training data by querying the model.', url: 'https://mltop10.info/', atlas: ['AML.T0024'], cwes: [], draft: true },
  { id: 'ML04', name: 'Membership Inference Attack', desc: 'Attacker determines whether a specific record was in the training set.', url: 'https://mltop10.info/', atlas: ['AML.T0025'], cwes: [], draft: true },
  { id: 'ML05', name: 'Model Theft', desc: 'Model functionality extracted via repeated queries.', url: 'https://mltop10.info/', atlas: ['AML.T0044'], cwes: [], draft: true },
  { id: 'ML06', name: 'AI Supply Chain Attacks', desc: 'Compromise of upstream datasets, pretrained models, or ML tooling dependencies.', url: 'https://mltop10.info/', atlas: ['AML.T0010'], cwes: ['CWE-1357'], draft: true },
  { id: 'ML07', name: 'Transfer Learning Attack', desc: 'Malicious pretrained model introduces backdoors when fine-tuned downstream.', url: 'https://mltop10.info/', atlas: ['AML.T0019'], cwes: [], draft: true },
  { id: 'ML08', name: 'Model Skewing', desc: 'Attacker feeds live feedback to shift model behavior over time.', url: 'https://mltop10.info/', atlas: ['AML.T0031'], cwes: [], draft: true },
  { id: 'ML09', name: 'Output Integrity Attack', desc: 'Model outputs are tampered with post-inference before reaching the consumer.', url: 'https://mltop10.info/', atlas: ['AML.T0047'], cwes: ['CWE-345'], draft: true },
  { id: 'ML10', name: 'Model Poisoning', desc: 'Attacker directly modifies model weights or serialized model artifacts.', url: 'https://mltop10.info/', atlas: ['AML.T0018'], cwes: ['CWE-506'], draft: true },
];

const LLM_TOP10 = [
  { id: 'LLM01', name: 'Prompt Injection', desc: 'User or retrieved content overrides system instructions or exfiltrates data.', url: 'https://genai.owasp.org/llmrisk/llm01-prompt-injection/', atlas: ['AML.T0051'], cwes: ['CWE-1352', 'CWE-74'], draft: false },
  { id: 'LLM02', name: 'Sensitive Information Disclosure', desc: 'Model leaks PII, credentials, or secrets through responses or logs.', url: 'https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/', atlas: ['AML.T0024', 'AML.T0025'], cwes: ['CWE-200', 'CWE-359'], draft: false },
  { id: 'LLM03', name: 'Supply Chain', desc: 'Compromised datasets, model providers, or plugins introduce backdoors.', url: 'https://genai.owasp.org/llmrisk/llm03-supply-chain/', atlas: ['AML.T0010'], cwes: ['CWE-1357'], draft: false },
  { id: 'LLM04', name: 'Data and Model Poisoning', desc: 'Training, fine-tuning, or RAG corpus manipulation changes model behavior.', url: 'https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/', atlas: ['AML.T0020', 'AML.T0018'], cwes: ['CWE-506'], draft: false },
  { id: 'LLM05', name: 'Improper Output Handling', desc: 'LLM outputs passed to downstream systems without sanitization.', url: 'https://genai.owasp.org/llmrisk/llm05-improper-output-handling/', atlas: [], cwes: ['CWE-116', 'CWE-79'], draft: false },
  { id: 'LLM06', name: 'Excessive Agency', desc: 'LLM agents granted overly broad permissions to act on external systems.', url: 'https://genai.owasp.org/llmrisk/llm06-excessive-agency/', atlas: [], cwes: ['CWE-250', 'CWE-269'], draft: false },
  { id: 'LLM07', name: 'System Prompt Leakage', desc: 'Internal system prompts containing secrets or logic are extracted by users.', url: 'https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/', atlas: ['AML.T0024'], cwes: ['CWE-200'], draft: false },
  { id: 'LLM08', name: 'Vector and Embedding Weaknesses', desc: 'RAG vector stores become injection or data leakage attack surface.', url: 'https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/', atlas: ['AML.T0020'], cwes: [], draft: false },
  { id: 'LLM09', name: 'Misinformation', desc: 'Model confidently generates false content causing harm or fraud.', url: 'https://genai.owasp.org/llmrisk/llm09-misinformation/', atlas: ['AML.T0048'], cwes: [], draft: false },
  { id: 'LLM10', name: 'Unbounded Consumption', desc: 'Uncontrolled inference cost or latency via abuse or missing rate limits.', url: 'https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/', atlas: [], cwes: ['CWE-400', 'CWE-770'], draft: false },
];

async function seed() {
  const client = await pool.connect();
  try {
    const colCheck = await client.query(
      `SELECT 1 FROM information_schema.columns WHERE table_name='owasp_top10' AND column_name='framework'`
    );
    if (colCheck.rows.length === 0) {
      console.error('ERROR: migration not applied — run scripts/migrate-owasp-framework.sql first');
      process.exit(1);
    }

    await client.query('BEGIN');

    const upsertSQL = `
      INSERT INTO owasp_top10 (category_id, name, description, url, cwe_ids, framework, atlas_technique_ids, is_draft, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
      ON CONFLICT (category_id, framework) DO UPDATE SET
        name = EXCLUDED.name,
        description = EXCLUDED.description,
        url = EXCLUDED.url,
        cwe_ids = EXCLUDED.cwe_ids,
        atlas_technique_ids = EXCLUDED.atlas_technique_ids,
        is_draft = EXCLUDED.is_draft,
        updated_at = now()
    `;

    for (const item of ML_TOP10) {
      await client.query(upsertSQL, [item.id, item.name, item.desc, item.url, item.cwes, 'ml-2023', item.atlas, item.draft]);
    }
    console.log(`  ✓ ML Top 10: ${ML_TOP10.length} categories`);

    for (const item of LLM_TOP10) {
      await client.query(upsertSQL, [item.id, item.name, item.desc, item.url, item.cwes, 'llm-2025', item.atlas, item.draft]);
    }
    console.log(`  ✓ LLM Top 10: ${LLM_TOP10.length} categories`);

    await client.query('COMMIT');
    console.log('Done. Cache TTL is 3600s — data visible within 1 hour.');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
    await pool.end();
  }
}

seed().catch((err) => { console.error(err); process.exit(1); });
