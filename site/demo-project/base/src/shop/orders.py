import json

import requests

from .models import Customer


def find_vip_orders(orders, vip_ids):
    vip = []
    for order in orders:
        if order["customer_id"] in vip_ids:
            vip.append(order)
    return vip


def load_customers(session, orders):
    customers = []
    for order in orders:
        customers.append(session.query(Customer).filter_by(id=order["customer_id"]).first())
    return customers


def enrich(orders):
    for order in orders:
        resp = requests.get(f"https://api.example.com/rates/{order['currency']}")
        order["rate"] = resp.json()["rate"]
    return orders


def render_receipt(lines):
    out = ""
    for line in lines:
        out += f"{line['sku']}: {line['qty']}\n"
    return out


def serialize(orders):
    payloads = []
    for order in orders:
        payloads.append(json.dumps(order))
    return payloads
