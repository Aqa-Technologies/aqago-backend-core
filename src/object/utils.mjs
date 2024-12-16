import { flatten } from "flat"
import isEqual from "lodash.isequal"

async function diffWithHooks(
  { prev, curr, hooks, prefix, strategies = ["merge"] },
  context = {}
) {
  async function _(key, val, _old, _new, context) {
    if (val instanceof Function && !isEqual(_old, _new)) {
      const ret = await val({
        _old,
        _new,
        ...context,
      })
      if (strategies.includes("throwOnFalsy") && !ret) {
        throw new Error(`Hook for key '${key}' returned falsy`)
      }
    }
  }
  const pre = prefix ? `${prefix}.` : ""
  await _(`${pre}_self`, flatten(hooks)[`${pre}_self`], prev, curr, {
    __prev: prev,
    __curr: curr,
    ...context,
  })
  const rawKeys = []
  if (strategies.includes("merge")) {
    rawKeys.push(
      ...Object.keys(flatten(curr ?? {})).concat(
        Object.keys(flatten(prev ?? {}))
      )
    )
  } else if (strategies.includes("patch")) {
    rawKeys.push(...Object.keys(flatten(curr ?? {})))
  }
  const keys = [...new Set(rawKeys)]
  const visited = []
  for (const key of keys) {
    let path = key
    while (path) {
      if (visited.includes(path)) {
        path = path.split(".").slice(0, -1).join(".")
        continue
      }
      await _(
        `${pre}${path}._self`,
        flatten(hooks)[`${pre}${path}._self`],
        prev && path.split(".").reduce((o, i) => (o ? o[i] : undefined), prev),
        curr && path.split(".").reduce((o, i) => (o ? o[i] : undefined), curr),
        { __prev: prev, __curr: curr, ...context }
      )
      await _(
        `${pre}${path}`,
        flatten(hooks)[`${pre}${path}`],
        prev && path.split(".").reduce((o, i) => (o ? o[i] : undefined), prev),
        curr && path.split(".").reduce((o, i) => (o ? o[i] : undefined), curr),
        { __prev: prev, __curr: curr, ...context }
      )
      visited.push(path)
      path = path.split(".").slice(0, -1).join(".")
    }
  }
}

export { diffWithHooks }
