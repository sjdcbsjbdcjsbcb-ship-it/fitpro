"""Export a redacted, read-only view of the deployed FastAPI source for review."""
import ast
import sys
from pathlib import Path

SAFE = set("""
GET POST PUT PATCH DELETE HEAD OPTIONS http https
products categories clients orders order_items partners waitlist flavors items
id name username tg tg_id telegram_id user_id first_name last_name ref ref_code code
title category sku brand image_url img description price qty quantity stock in_stock total
order_id product_id flavor created_at source message admin_id ok detail error
initData init_data user auth_date hash query_id start_param
Authorization Content-Type application/json basic Basic utf-8 sha256
* Стандарт
""".split())
ROUTES = set("""
/ /admin.js /api/init /api/admin/clients /api/order /api/products
/api/products/{id} /api/products/{product_id} /api/products/{pid}
/api/categories /api/categories/rename /api/categories/delete /api/upload-photo
/api/import-price /api/track /api/partners /api/crm-summary /uploads /static
""".split())

class Redact(ast.NodeTransformer):
    def visit_Constant(self, node):
        value = node.value
        if isinstance(value, str) and value not in SAFE and value not in ROUTES:
            node.value = "[redacted]"
        elif isinstance(value, bytes):
            node.value = b"[redacted]"
        elif isinstance(value, (int, float)) and abs(value) > 65535:
            node.value = 0
        return node

def export(path):
    tree = ast.parse(path.read_bytes())
    tree = Redact().visit(tree)
    return ast.unparse(tree)

if __name__ == "__main__":
    print(export(Path(sys.argv[1])))
