# Day 12 – State Management Cleanup

## Goal
Refactor and clarify Sentinel's runtime state handling to remove
implicit behavior and improve architectural clarity.

## What was wrong before
- State was tracked only as (ip, action)
- Execution cooldowns and alerts were conflated
- No clear separation between detection and response memory
- Future extension would have caused state leakage

## What was changed
- Introduced a centralized in-memory STATE per IP
- Separated:
  - action execution cooldowns
  - alert history
- State now acts as a single source of truth for runtime memory

## Current responsibilities of state.py
- Track action execution and cooldowns
- Track alert history per IP
- Provide introspection for debugging
- No detection or decision logic

## What is intentionally NOT implemented
- Persistent storage (disk / DB)
- Cross-IP correlation
- Attack severity tracking

## Outcome
- Cleaner architecture
- Safer future extensions
- Clear boundary between detection and response
