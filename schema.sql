-- DefectDojo-inspired relational schema required by CyberSentinel Module 1.
CREATE TABLE IF NOT EXISTS product (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS engagement (
    id SERIAL PRIMARY KEY,
    product_id INT REFERENCES product(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'In Progress',
    target_url VARCHAR(500) NOT NULL,
    start_time TIMESTAMPTZ DEFAULT NOW(),
    end_time TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS test (
    id SERIAL PRIMARY KEY,
    engagement_id INT REFERENCES engagement(id) ON DELETE CASCADE,
    test_type VARCHAR(100) NOT NULL,
    raw_output JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS finding (
    id SERIAL PRIMARY KEY,
    test_id INT REFERENCES test(id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,
    severity VARCHAR(20) CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Info')),
    cwe INT,
    description TEXT,
    mitigation TEXT,
    payload TEXT,
    hash_code VARCHAR(64) NOT NULL,
    duplicate BOOLEAN DEFAULT FALSE,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS endpoint (
    id SERIAL PRIMARY KEY,
    product_id INT REFERENCES product(id) ON DELETE CASCADE,
    protocol VARCHAR(10),
    host VARCHAR(255) NOT NULL,
    port INT NOT NULL,
    path VARCHAR(500),
    query TEXT,
    UNIQUE(protocol, host, port, path, query)
);

CREATE TABLE IF NOT EXISTS endpoint_status (
    id SERIAL PRIMARY KEY,
    finding_id INT REFERENCES finding(id) ON DELETE CASCADE,
    endpoint_id INT REFERENCES endpoint(id) ON DELETE CASCADE,
    mitigated BOOLEAN DEFAULT FALSE,
    false_positive BOOLEAN DEFAULT FALSE,
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(finding_id, endpoint_id)
);

CREATE INDEX IF NOT EXISTS finding_hash_code_idx ON finding(hash_code);
CREATE INDEX IF NOT EXISTS engagement_product_id_idx ON engagement(product_id);
CREATE INDEX IF NOT EXISTS test_engagement_id_idx ON test(engagement_id);
