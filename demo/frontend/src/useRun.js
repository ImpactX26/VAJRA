import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * Streams one demo run from the backend (SSE) and replays its events at a
 * presenter-controlled pace, so judges can follow each orchestration hop.
 */
export function useRun(delay, paused) {
  const [events, setEvents] = useState([])
  const [phase, setPhase] = useState('idle') // idle | running | done
  const queue = useRef([])
  const streamDone = useRef(true)
  const source = useRef(null)
  const resolver = useRef(null)

  const step = useCallback(() => {
    if (queue.current.length) {
      const ev = queue.current.shift()
      setEvents((prev) => [...prev, ev])
      return
    }
    if (streamDone.current && resolver.current) {
      const resolve = resolver.current
      resolver.current = null
      setPhase('done')
      resolve()
    }
  }, [])

  useEffect(() => {
    if (paused) return undefined
    const id = setInterval(step, delay)
    return () => clearInterval(id)
  }, [delay, paused, step])

  useEffect(() => () => source.current?.close(), [])

  const reset = useCallback(() => {
    source.current?.close()
    queue.current = []
    streamDone.current = true
    resolver.current?.()
    resolver.current = null
    setEvents([])
    setPhase('idle')
  }, [])

  const start = useCallback(
    (params) =>
      new Promise((resolve) => {
        reset()
        streamDone.current = false
        resolver.current = resolve
        setPhase('running')
        const es = new EventSource(`/api/run?${new URLSearchParams(params)}`)
        source.current = es
        es.onmessage = (msg) => {
          const ev = JSON.parse(msg.data)
          if (ev.type === 'done') {
            streamDone.current = true
            es.close()
          } else {
            queue.current.push(ev)
          }
        }
        es.onerror = () => {
          if (!streamDone.current) {
            queue.current.push({ type: 'error', message: 'Lost connection to the demo backend (is it running on :8000?)' })
            streamDone.current = true
          }
          es.close()
        }
      }),
    [reset],
  )

  return { events, phase, start, step, reset }
}
