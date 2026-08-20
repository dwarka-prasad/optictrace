MERGE INTO products (sku, name, price, stock) KEY(sku) VALUES
  ('SKU-100', 'Mechanical keyboard', 129.00, 42),
  ('SKU-200', '27" monitor',         349.00, 7),
  ('SKU-300', 'Desk lamp',            39.50, 0),
  ('SKU-400', 'USB-C dock',          189.00, 15);
