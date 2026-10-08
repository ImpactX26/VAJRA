// Consistent line icons (24x24 grid, 2px stroke, round caps) used across the UI instead of emoji.

const P = (d) => ({ t: 'path', d })
const C = (cx, cy, r) => ({ t: 'circle', cx, cy, r })
const R = (x, y, width, height, rx = 0) => ({ t: 'rect', x, y, width, height, rx })

const SHIELD = 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'

const ICONS = {
  shield: [P(SHIELD)],
  'shield-check': [P(SHIELD), P('m9 12 2 2 4-4')],
  'shield-alert': [P(SHIELD), P('M12 8v4'), P('M12 16h.01')],
  alert: [P('M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z'), P('M12 9v4'), P('M12 17h.01')],
  check: [P('M20 6 9 17l-5-5')],
  'check-circle': [C(12, 12, 10), P('m8 12 3 3 5-6')],
  x: [P('M18 6 6 18'), P('M6 6l12 12')],
  ban: [C(12, 12, 10), P('m4.9 4.9 14.2 14.2')],
  lock: [R(3, 11, 18, 11, 2), P('M7 11V7a5 5 0 0 1 10 0v4')],
  flame: [P('M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.07-2.14-.22-4.05 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.15.43-2.29 1-3a2.5 2.5 0 0 0 2.5 2.5z')],
  file: [P('M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z'), P('M14 2v6h6')],
  folder: [P('M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2z')],
  globe: [C(12, 12, 10), P('M2 12h20'), P('M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z')],
  mail: [R(2, 4, 20, 16, 2), P('m22 7-10 6L2 7')],
  user: [P('M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2'), C(12, 7, 4)],
  message: [P('M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z')],
  server: [R(2, 2, 20, 8, 2), R(2, 14, 20, 8, 2), P('M6 6h.01'), P('M6 18h.01')],
  monitor: [R(2, 3, 20, 14, 2), P('M8 21h8'), P('M12 17v4')],
  cpu: [R(5, 5, 14, 14, 2), R(9, 9, 6, 6), P('M9 1v4'), P('M15 1v4'), P('M9 19v4'), P('M15 19v4'), P('M1 9h4'), P('M1 15h4'), P('M19 9h4'), P('M19 15h4')],
  play: [P('M6 3l14 9-14 9V3z')],
  pause: [R(6, 4, 4, 16, 1), R(14, 4, 4, 16, 1)],
  'skip-forward': [P('M5 4l10 8-10 8V4z'), P('M19 5v14')],
  stop: [R(5, 5, 14, 14, 2)],
  refresh: [P('M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8'), P('M21 3v5h-5'), P('M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16'), P('M8 16H3v5')],
  external: [P('M15 3h6v6'), P('M10 14 21 3'), P('M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6')],
  'chevron-down': [P('m6 9 6 6 6-6')],
  'chevron-right': [P('m9 18 6-6-6-6')],
  'arrow-right': [P('M5 12h14'), P('m12 5 7 7-7 7')],
  search: [C(11, 11, 8), P('m21 21-4.3-4.3')],
  layers: [P('m12 2 10 5-10 5L2 7l10-5z'), P('m2 17 10 5 10-5'), P('m2 12 10 5 10-5')],
  activity: [P('M22 12h-4l-3 9L9 3l-3 9H2')],
  package: [P('M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z'), P('M3.3 7 12 12l8.7-5'), P('M12 22V12')],
  key: [C(7.5, 15.5, 5.5), P('m21 2-9.6 9.6'), P('m15.5 7.5 3 3L22 7l-3-3')],
  eye: [P('M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7z'), C(12, 12, 3)],
  info: [C(12, 12, 10), P('M12 16v-4'), P('M12 8h.01')],
  zap: [P('M13 2 3 14h9l-1 8 10-12h-9l1-8z')],
  flask: [P('M9 3h6'), P('M10 3v6.5L4.5 19a1.5 1.5 0 0 0 1.3 2.3h12.4a1.5 1.5 0 0 0 1.3-2.3L14 9.5V3')],
  inbox: [P('M22 12h-6l-2 3h-4l-2-3H2'), P('M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z')],
  copy: [R(9, 9, 13, 13, 2), P('M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1')],
  chart: [P('M3 3v18h18'), P('M18 17V9'), P('M13 17V5'), P('M8 17v-3')],
  book: [P('M4 19.5A2.5 2.5 0 0 1 6.5 17H20'), P('M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z')],
  target: [C(12, 12, 10), C(12, 12, 6), C(12, 12, 2)],
  tag: [P('M12.59 2.59A2 2 0 0 0 11.17 2H4a2 2 0 0 0-2 2v7.17a2 2 0 0 0 .59 1.41l8.83 8.83a2 2 0 0 0 2.83 0l7.17-7.17a2 2 0 0 0 0-2.83z'), P('M7 7h.01')],
  send: [P('m22 2-7 20-4-9-9-4z'), P('M22 2 11 13')],
  arrow: [P('M5 12h14')],
  tool: [P('M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z')],
  clock: [C(12, 12, 10), P('M12 6v6l4 2')],
  dot: [C(12, 12, 4)],
}

export function Icon({ name, size = 16, className = '', title, strokeWidth = 2, ...rest }) {
  const parts = ICONS[name] || ICONS.dot
  return (
    <svg
      className={`icon ${className}`}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      role={title ? 'img' : undefined}
      aria-hidden={title ? undefined : true}
      aria-label={title}
      {...rest}
    >
      {title && <title>{title}</title>}
      {parts.map(({ t, ...a }, i) => {
        if (t === 'path') return <path key={i} d={a.d} />
        if (t === 'circle') return <circle key={i} {...a} />
        return <rect key={i} {...a} />
      })}
    </svg>
  )
}
