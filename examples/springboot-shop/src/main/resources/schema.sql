-- The example's own data, so a db span times a real query.
CREATE TABLE IF NOT EXISTS products (
  sku    VARCHAR(16) PRIMARY KEY,
  name   VARCHAR(64) NOT NULL,
  price  DECIMAL(10,2) NOT NULL,
  stock  INT NOT NULL
);
CREATE TABLE IF NOT EXISTS orders (
  order_ref VARCHAR(32) PRIMARY KEY,
  sku       VARCHAR(16) NOT NULL,
  qty       INT NOT NULL,
  amount    DECIMAL(10,2) NOT NULL,
  -- Deliberately here: an email in a WHERE clause is the normal way customer
  -- data ends up inside a captured statement, which is what span attribute
  -- redaction exists for.
  email     VARCHAR(128) NOT NULL
);
