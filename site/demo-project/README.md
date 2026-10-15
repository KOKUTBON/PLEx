# PLEx demo project

Intentionally slow example code used to generate the interactive report on the
PLEx website. `base/` is the `main` branch snapshot and `head/` is a pull request
that introduces a complexity regression in `find_vip_orders` and a new
quadratic `dedupe` helper.

Regenerate the site data with:

```bash
python scripts/build_site_data.py
```
