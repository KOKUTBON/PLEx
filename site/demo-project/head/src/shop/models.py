from dataclasses import dataclass


@dataclass
class Customer:
    id: int
    name: str
    tier: str = "standard"
