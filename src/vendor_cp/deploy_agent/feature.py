"""Retained signed deployment evidence, without a second fleet owner."""

from dataclasses import replace

from vendor_cp.deploy_agent.declaration import declaration

from .router import router

feature = replace(declaration, routers=[router])
