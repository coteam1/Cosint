# Vendored assets

`cytoscape.min.js` (v3.28.1, MIT) is bundled so the relationship graph works
with no outbound internet. To update:

```bash
npm pack cytoscape@3.28.1 && tar -xzf cytoscape-3.28.1.tgz
cp package/dist/cytoscape.min.js app/static/vendor/
```

Fonts still come from Google Fonts and degrade to system Arabic faces offline.
