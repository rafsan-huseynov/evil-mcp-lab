import pkgutil
import importlib

def all_modules():
    import server.attacks as pkg
    mods = {}
    for m in pkgutil.iter_modules(pkg.__path__):
        if m.name.startswith("_"):
            continue
        mods[m.name] = importlib.import_module(f"server.attacks.{m.name}")
    return mods

def enabled_modules():
    import config
    return [mod for name, mod in all_modules().items()
            if config.ATTACKS_ENABLED.get(name, True)]
