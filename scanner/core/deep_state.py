"""Deep-state SPA storage mutation and multi-step wizard exploration."""
from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple


PRIVILEGE_HINTS = (
    "admin",
    "role",
    "staff",
    "internal",
    "manage",
    "feature",
    "flag",
    "beta",
    "premium",
    "subscription",
    "entitlement",
    "access",
    "can",
    "allow",
    "permission",
    "wizard",
    "step",
    "complete",
    "completed",
    "onboarding",
    "tour",
)

ROLE_UPGRADES = {
    "user": "admin",
    "viewer": "admin",
    "guest": "admin",
    "member": "admin",
    "read_only": "admin",
    "readonly": "admin",
    "basic": "enterprise",
    "free": "enterprise",
    "pending": "approved",
    "disabled": "enabled",
}


def _matches_hint(key: str) -> bool:
    lowered = str(key or "").lower()
    return any(hint in lowered for hint in PRIVILEGE_HINTS)


def _mutate_scalar(key: str, value: Any) -> Tuple[Any, Optional[str]]:
    """Return a privileged variant of a scalar value when it looks stateful."""
    if isinstance(value, bool):
        if _matches_hint(key) and value is False:
            return True, "flipped privileged boolean"
        return value, None

    if isinstance(value, int):
        if _matches_hint(key) and value <= 1:
            if "step" in key.lower():
                return 99, "jumped wizard step"
            return 1, "raised numeric flag"
        return value, None

    if not isinstance(value, str):
        return value, None

    lowered = value.strip().lower()
    if not lowered:
        return value, None

    truthy_upgrades = {
        "false": "true",
        "no": "yes",
        "off": "on",
        "0": "1",
        "disabled": "enabled",
    }
    if lowered in truthy_upgrades and _matches_hint(key):
        upgraded = truthy_upgrades[lowered]
        if value.isupper():
            upgraded = upgraded.upper()
        return upgraded, "flipped stored state"

    if lowered in ROLE_UPGRADES and (_matches_hint(key) or lowered in ROLE_UPGRADES):
        upgraded = ROLE_UPGRADES[lowered]
        if value.isupper():
            upgraded = upgraded.upper()
        return upgraded, "upgraded role-like value"

    if lowered.isdigit() and _matches_hint(key):
        if "step" in key.lower():
            return "99", "jumped wizard step"
        if lowered == "0":
            return "1", "raised numeric flag"

    return value, None


def _mutate_nested_value(key: str, value: Any, depth: int = 0, max_changes: int = 8) -> Tuple[Any, List[Dict[str, Any]]]:
    """Recursively mutate JSON-ish structures and return a mutation log."""
    if depth > 3 or max_changes <= 0:
        return value, []

    changed: List[Dict[str, Any]] = []

    if isinstance(value, dict):
        result = deepcopy(value)
        for child_key in list(result.keys()):
            if len(changed) >= max_changes:
                break
            mutated, child_changes = _mutate_nested_value(
                str(child_key),
                result[child_key],
                depth + 1,
                max_changes - len(changed),
            )
            if child_changes:
                result[child_key] = mutated
                changed.extend(child_changes)
        return result, changed

    if isinstance(value, list):
        result = deepcopy(value)
        for idx, item in enumerate(list(result)):
            if len(changed) >= max_changes:
                break
            mutated, child_changes = _mutate_nested_value(
                f"{key}[{idx}]",
                item,
                depth + 1,
                max_changes - len(changed),
            )
            if child_changes:
                result[idx] = mutated
                changed.extend(child_changes)
        return result, changed

    mutated, reason = _mutate_scalar(key, value)
    if reason:
        return mutated, [{"key": key, "before": value, "after": mutated, "reason": reason}]
    return value, []


def _mutate_storage_entry(key: str, raw_value: str) -> Tuple[str, List[Dict[str, Any]]]:
    """Mutate a browser storage string while preserving its outer representation."""
    if raw_value is None:
        return "", []

    mutated_scalar, reason = _mutate_scalar(key, raw_value)
    if reason:
        return str(mutated_scalar), [{"key": key, "before": raw_value, "after": mutated_scalar, "reason": reason}]

    text = str(raw_value).strip()
    if not text or not text.startswith(("{", "[")):
        return str(raw_value), []

    try:
        parsed = json.loads(text)
    except Exception:
        return str(raw_value), []

    mutated, changes = _mutate_nested_value(key, parsed)
    if not changes:
        return str(raw_value), []

    return json.dumps(mutated, separators=(",", ":")), changes


def build_storage_mutation_plan(snapshot: Dict[str, Any], max_mutations: int = 16) -> Dict[str, Any]:
    """Create a bounded mutation plan for browser storage and IndexedDB records."""
    plan = {
        "localStorage": {},
        "sessionStorage": {},
        "indexedDB": [],
        "mutations": [],
    }

    for bucket_name in ("localStorage", "sessionStorage"):
        bucket = dict((snapshot or {}).get(bucket_name, {}) or {})
        for key, raw_value in bucket.items():
            if len(plan["mutations"]) >= max_mutations:
                break
            mutated, changes = _mutate_storage_entry(str(key), "" if raw_value is None else str(raw_value))
            if not changes or mutated == raw_value:
                continue
            plan[bucket_name][str(key)] = mutated
            for change in changes:
                plan["mutations"].append(
                    {
                        "location": bucket_name,
                        "key": str(key),
                        "before": change.get("before"),
                        "after": change.get("after"),
                        "reason": change.get("reason"),
                    }
                )

    indexed_dbs = list((snapshot or {}).get("indexedDB", []) or [])
    for db in indexed_dbs:
        if len(plan["mutations"]) >= max_mutations:
            break
        db_patch = {"name": db.get("name", ""), "stores": []}
        for store in db.get("stores", []) or []:
            if len(plan["mutations"]) >= max_mutations:
                break
            store_patch = {"name": store.get("name", ""), "records": []}
            for record in store.get("records", []) or []:
                if len(plan["mutations"]) >= max_mutations:
                    break
                value = record.get("value")
                mutated, changes = _mutate_nested_value(
                    f"{db.get('name', 'db')}.{store.get('name', 'store')}",
                    value,
                )
                if not changes or mutated == value:
                    continue
                store_patch["records"].append(
                    {
                        "primaryKey": record.get("primaryKey"),
                        "value": mutated,
                    }
                )
                for change in changes:
                    plan["mutations"].append(
                        {
                            "location": "indexedDB",
                            "key": f"{db.get('name', '')}.{store.get('name', '')}",
                            "before": change.get("before"),
                            "after": change.get("after"),
                            "reason": change.get("reason"),
                        }
                    )
            if store_patch["records"]:
                db_patch["stores"].append(store_patch)
        if db_patch["stores"]:
            plan["indexedDB"].append(db_patch)

    return plan


class DeepStateMutator:
    """Mutate client-side state to reveal hidden SPA routes, forms, and actions."""

    def __init__(self, max_mutations: int = 16, max_wizard_steps: int = 4) -> None:
        self.max_mutations = max_mutations
        self.max_wizard_steps = max_wizard_steps

    async def mutate_page(self, page) -> Dict[str, Any]:
        before = await self.snapshot(page)
        plan = build_storage_mutation_plan(before, max_mutations=self.max_mutations)

        if plan.get("mutations"):
            await self._apply_plan(page, plan)
            try:
                await page.reload(wait_until="domcontentloaded", timeout=4000)
            except Exception:
                pass
            await page.wait_for_timeout(900)

        wizard_trace = await self._advance_wizard(page)
        await page.wait_for_timeout(700)

        after = await self.snapshot(page)
        revealed = await self._collect_revealed_state(page)
        return {
            "mutations": plan.get("mutations", []),
            "wizard": wizard_trace,
            "before": self._summarize_snapshot(before),
            "after": self._summarize_snapshot(after),
            "revealed": revealed,
        }

    async def snapshot(self, page) -> Dict[str, Any]:
        """Capture a minimal serializable browser state snapshot."""
        try:
            return await page.evaluate(
                """
                async () => {
                    const readStorage = storage => {
                        const out = {};
                        for (let i = 0; i < storage.length; i += 1) {
                            const key = storage.key(i);
                            out[key] = storage.getItem(key);
                        }
                        return out;
                    };

                    const indexedDBSnapshot = [];
                    if (window.indexedDB && typeof indexedDB.databases === 'function') {
                        try {
                            const dbs = await indexedDB.databases();
                            for (const meta of (dbs || []).slice(0, 3)) {
                                const name = meta && meta.name;
                                if (!name) continue;
                                const snapshotDb = await new Promise(resolve => {
                                    const request = indexedDB.open(name);
                                    request.onerror = () => resolve(null);
                                    request.onsuccess = () => {
                                        const db = request.result;
                                        const stores = [];
                                        const storeNames = Array.from(db.objectStoreNames || []).slice(0, 4);
                                        const collectStore = storeName => new Promise(storeResolve => {
                                            try {
                                                const tx = db.transaction(storeName, 'readonly');
                                                const store = tx.objectStore(storeName);
                                                const records = [];
                                                const cursorReq = store.openCursor();
                                                cursorReq.onerror = () => storeResolve({ name: storeName, records });
                                                cursorReq.onsuccess = event => {
                                                    const cursor = event.target.result;
                                                    if (!cursor || records.length >= 3) {
                                                        storeResolve({ name: storeName, records });
                                                        return;
                                                    }
                                                    try {
                                                        records.push({
                                                            primaryKey: cursor.primaryKey,
                                                            value: cursor.value,
                                                        });
                                                    } catch (_) {}
                                                    cursor.continue();
                                                };
                                            } catch (_) {
                                                storeResolve({ name: storeName, records: [] });
                                            }
                                        });

                                        Promise.all(storeNames.map(collectStore)).then(storeSnapshots => {
                                            try { db.close(); } catch (_) {}
                                            resolve({ name, stores: storeSnapshots });
                                        });
                                    };
                                });
                                if (snapshotDb) indexedDBSnapshot.push(snapshotDb);
                            }
                        } catch (_) {}
                    }

                    return {
                        localStorage: readStorage(window.localStorage),
                        sessionStorage: readStorage(window.sessionStorage),
                        indexedDB: indexedDBSnapshot,
                    };
                }
                """
            )
        except Exception:
            return {"localStorage": {}, "sessionStorage": {}, "indexedDB": []}

    async def _apply_plan(self, page, plan: Dict[str, Any]) -> None:
        try:
            await page.evaluate(
                """
                async mutationPlan => {
                    for (const [key, value] of Object.entries(mutationPlan.localStorage || {})) {
                        window.localStorage.setItem(key, value);
                    }
                    for (const [key, value] of Object.entries(mutationPlan.sessionStorage || {})) {
                        window.sessionStorage.setItem(key, value);
                    }

                    const dbPatches = mutationPlan.indexedDB || [];
                    for (const dbPatch of dbPatches) {
                        await new Promise(resolve => {
                            try {
                                const request = indexedDB.open(dbPatch.name);
                                request.onerror = () => resolve();
                                request.onsuccess = () => {
                                    const db = request.result;
                                    const storePatches = dbPatch.stores || [];
                                    Promise.all(storePatches.map(storePatch => new Promise(storeResolve => {
                                        try {
                                            const tx = db.transaction(storePatch.name, 'readwrite');
                                            const store = tx.objectStore(storePatch.name);
                                            for (const record of (storePatch.records || [])) {
                                                if (record.primaryKey === undefined) {
                                                    store.put(record.value);
                                                } else {
                                                    store.put(record.value, record.primaryKey);
                                                }
                                            }
                                            tx.oncomplete = () => storeResolve();
                                            tx.onerror = () => storeResolve();
                                        } catch (_) {
                                            storeResolve();
                                        }
                                    }))).then(() => {
                                        try { db.close(); } catch (_) {}
                                        resolve();
                                    });
                                };
                            } catch (_) {
                                resolve();
                            }
                        });
                    }

                    window.dispatchEvent(new StorageEvent('storage'));
                }
                """,
                plan,
            )
        except Exception:
            return

    async def _advance_wizard(self, page) -> Dict[str, Any]:
        filled_fields = 0
        clicked_steps: List[str] = []

        try:
            filled_fields = int(
                await page.evaluate(
                    """
                    () => {
                        const visible = el => {
                            const style = window.getComputedStyle(el);
                            return style.display !== 'none' && style.visibility !== 'hidden';
                        };
                        const fillText = el => {
                            const type = (el.type || '').toLowerCase();
                            if (type === 'hidden' || type === 'submit' || type === 'button') return false;
                            if (type === 'checkbox' || type === 'radio') {
                                el.checked = true;
                                el.dispatchEvent(new Event('change', { bubbles: true }));
                                return true;
                            }
                            if (el.tagName === 'SELECT') {
                                const option = Array.from(el.options || []).find(o => !o.disabled && o.value);
                                if (option) {
                                    el.value = option.value;
                                    el.dispatchEvent(new Event('change', { bubbles: true }));
                                    return true;
                                }
                                return false;
                            }
                            const name = (el.name || el.id || '').toLowerCase();
                            let value = 'scanner-demo';
                            if (name.includes('mail')) value = 'scanner@example.test';
                            else if (name.includes('phone')) value = '5550100';
                            else if (name.includes('password')) value = 'Admin123!';
                            else if (name.includes('code') || name.includes('otp')) value = '000000';
                            else if (name.includes('url') || name.includes('site')) value = 'https://example.test';
                            el.value = value;
                            el.dispatchEvent(new Event('input', { bubbles: true }));
                            el.dispatchEvent(new Event('change', { bubbles: true }));
                            return true;
                        };

                        let count = 0;
                        for (const el of Array.from(document.querySelectorAll('input, textarea, select')).slice(0, 20)) {
                            if (!visible(el)) continue;
                            if (fillText(el)) count += 1;
                        }
                        return count;
                    }
                    """
                )
            )
        except Exception:
            filled_fields = 0

        for _ in range(self.max_wizard_steps):
            try:
                clicked = await page.evaluate(
                    """
                    () => {
                        const textFor = el => (el.innerText || el.textContent || '').trim();
                        const candidates = Array.from(
                            document.querySelectorAll('button, [role="button"], input[type="submit"], a')
                        )
                            .filter(el => !el.disabled)
                            .map(el => ({ el, text: textFor(el) }))
                            .filter(item => /next|continue|review|confirm|finish|complete|proceed|submit/i.test(item.text));
                        if (!candidates.length) return null;
                        candidates[0].el.click();
                        return candidates[0].text;
                    }
                    """
                )
            except Exception:
                clicked = None

            if not clicked:
                break
            clicked_steps.append(str(clicked))
            try:
                await page.wait_for_timeout(700)
            except Exception:
                break

        return {"filled_fields": filled_fields, "clicked_steps": clicked_steps}

    async def _collect_revealed_state(self, page) -> Dict[str, Any]:
        try:
            return await page.evaluate(
                """
                () => {
                    const hits = [];
                    for (const el of Array.from(document.querySelectorAll('a, button, [role="button"], form')).slice(0, 80)) {
                        const text = ((el.innerText || el.textContent || '') + ' ' + (el.getAttribute('href') || '') + ' ' + (el.getAttribute('action') || '')).trim();
                        if (/admin|manage|settings|billing|users|reports|internal|staff/i.test(text)) {
                            hits.push(text.slice(0, 120));
                        }
                    }
                    return {
                        privilegedHints: hits.slice(0, 12),
                        count: hits.length,
                    };
                }
                """
            )
        except Exception:
            return {"privilegedHints": [], "count": 0}

    def _summarize_snapshot(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "localStorageKeys": len((snapshot or {}).get("localStorage", {}) or {}),
            "sessionStorageKeys": len((snapshot or {}).get("sessionStorage", {}) or {}),
            "indexedDBCount": len((snapshot or {}).get("indexedDB", []) or []),
        }
