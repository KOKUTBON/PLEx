import json

import requests

from .models import Customer


def find_vip_orders(orders, vip_ids):
    vip = []
    for order in orders:
        for vip_id in vip_ids:
            if order["customer_id"] == vip_id:
                vip.append(order)
    vip.sort(key=lambda o: o["total"], reverse=True)
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


def dedupe(orders):
    unique = []
    for order in orders:
        for seen in unique:
            if seen["id"] == order["id"]:
                break
        else:
            unique.append(order)
    unique.sort(key=lambda o: o["id"])
    return unique


def serialize(orders):
    payloads = []
    for order in orders:
        payloads.append(json.dumps(order))
    return payloads
