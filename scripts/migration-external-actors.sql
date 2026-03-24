CREATE TABLE IF NOT EXISTS external_actors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  source VARCHAR(50) NOT NULL DEFAULT 'thaicert',
  country VARCHAR(10),
  category VARCHAR(50),
  synonyms TEXT[],
  refs TEXT[],
  mitre_group_id VARCHAR(20),
  uuid VARCHAR(100) UNIQUE,
  motivation TEXT,
  first_seen VARCHAR(50),
  suspected_victims TEXT[],
  target_categories TEXT[],
  suspected_state_sponsor VARCHAR(100),
  attribution_confidence VARCHAR(50),
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_external_actors_name ON external_actors(name);
CREATE INDEX IF NOT EXISTS idx_external_actors_source ON external_actors(source);
CREATE INDEX IF NOT EXISTS idx_external_actors_country ON external_actors(country);
CREATE INDEX IF NOT EXISTS idx_external_actors_search ON external_actors USING GIN (to_tsvector('english', COALESCE(name, '') || ' ' || COALESCE(description, '')));
