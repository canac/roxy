export const onResponse = (req, res) => {
  res.headers.set('X-Roxy', '0.1.0');
  return res;
}
