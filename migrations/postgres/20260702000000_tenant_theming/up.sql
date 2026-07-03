ALTER TABLE organizations ADD COLUMN theme_preset TEXT;
ALTER TABLE organizations ADD COLUMN brand_primary TEXT;
ALTER TABLE organizations ADD COLUMN brand_on_primary TEXT;
ALTER TABLE organizations ADD COLUMN brand_secondary TEXT;
ALTER TABLE organizations ADD COLUMN public_login_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE organizations ADD COLUMN public_login_approved INTEGER NOT NULL DEFAULT 0;
