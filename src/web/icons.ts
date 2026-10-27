/** Inline 16x16 SVG icons. Stroke icons use currentColor. */

const S = 'fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"';

const ICONS = {
  open:
    '<path d="M1.5 3.5h4.2l1.4 1.5h6.4v8.5H1.5z" fill="#f0c75e" stroke="#b08a2a" stroke-width="1"/>' +
    '<path d="M1.5 6.5h12" stroke="#b08a2a" stroke-width="1"/>',
  close:
    `<path d="M3.5 1.5h6l3 3v10h-9z" ${S}/><path d="M9.5 1.5v3h3" ${S}/>` +
    '<path d="M6 8.5l3.5 3.5M9.5 8.5 6 12" stroke="#d0342c" stroke-width="1.5" stroke-linecap="round"/>',
  fin:
    '<path d="M1.5 13.5C5.5 12 8.7 8 9.6 1.8c2.3 3.4 3.9 7.4 4.6 11.7z" fill="#2f7ad6"/>' +
    '<path d="M.8 14.6c1.2-.7 2.4-.7 3.6 0s2.4.7 3.6 0 2.4-.7 3.6 0 2.4.7 3.6 0" fill="none" stroke="#2f7ad6" stroke-width="1.1"/>',
  stop: '<rect x="3" y="3" width="10" height="10" rx="1.2" fill="#d9302c"/>',
  options:
    `<path d="M2 4h12M2 8h12M2 12h12" ${S}/>` +
    '<circle cx="5" cy="4" r="1.7" fill="var(--btn-bg, #fff)" stroke="currentColor" stroke-width="1.3"/>' +
    '<circle cx="10.5" cy="8" r="1.7" fill="var(--btn-bg, #fff)" stroke="currentColor" stroke-width="1.3"/>' +
    '<circle cx="6.5" cy="12" r="1.7" fill="var(--btn-bg, #fff)" stroke="currentColor" stroke-width="1.3"/>',
  stats:
    '<path d="M1.5 14.5h13" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>' +
    '<rect x="2.5" y="8" width="2.6" height="5.5" fill="#4b8fd8"/><rect x="6.7" y="3" width="2.6" height="10.5" fill="#e3a33a"/>' +
    '<rect x="10.9" y="6" width="2.6" height="7.5" fill="#5cae5c"/>',
  goto: `<path d="M1.5 8h9M7.5 4.5 11 8l-3.5 3.5" ${S}/><path d="M14 2.5v11" ${S}/>`,
  marks: `<path d="M4 1.5h8v13l-4-3.2-4 3.2z" ${S}/>`,
  autoscroll: `<path d="M8 1.8v9M4.5 7.5 8 11l3.5-3.5" ${S}/><path d="M2.5 14h11" ${S}/>`,
  wireshark:
    '<rect x="1" y="1" width="14" height="14" rx="3" fill="#1679c2"/>' +
    '<path d="M3.2 12.3c2.8-1 4.8-3.6 5.4-8.4 1.5 2.6 2.8 5.5 3.3 8.4z" fill="#fff"/>',
  refresh: `<path d="M13 8a5 5 0 1 1-1.5-3.6" ${S}/><path d="M12 1.8v3h-3" ${S}/>`,
  bookmark: '<path d="M4 1.5h8v13l-4-3.2-4 3.2z" fill="currentColor" stroke="currentColor" stroke-width="1" stroke-linejoin="round"/>',
  clear: '<circle cx="8" cy="8" r="6.2" fill="currentColor" opacity=".55"/><path d="M5.6 5.6l4.8 4.8M10.4 5.6l-4.8 4.8" stroke="var(--panel, #fff)" stroke-width="1.5" stroke-linecap="round"/>',
  apply: `<path d="M2.5 8h10M8.5 4l4 4-4 4" ${S} stroke-width="1.6"/>`,
  chevron: `<path d="M4 6l4 4 4-4" ${S}/>`,
  up: `<path d="M8 13.5V3M4 6.5 8 2.5l4 4" ${S}/>`,
  folder: '<path d="M1.5 3.5h4.2l1.4 1.5h7.4v8.5h-13z" fill="#f0c75e" stroke="#b08a2a" stroke-width="1"/>',
  file:
    '<path d="M3.5 1.5h6l3 3v10h-9z" fill="var(--panel, #fff)" stroke="currentColor" stroke-width="1"/>' +
    '<path d="M9.5 1.5v3h3" fill="none" stroke="currentColor" stroke-width="1"/>' +
    '<path d="M5.5 8h5M5.5 10h5M5.5 12h3" stroke="#2f7ad6" stroke-width="1"/>',
  history: `<circle cx="8" cy="8" r="6" ${S}/><path d="M8 4.5V8l2.5 1.5" ${S}/>`,
  sparkle: '<path d="M8 1c.5 3.6 2.4 5.5 6 6-3.6.5-5.5 2.4-6 6-.5-3.6-2.4-5.5-6-6 3.6-.5 5.5-2.4 6-6z" fill="currentColor"/>',
  x: `<path d="M4 4l8 8M12 4l-8 8" ${S} stroke-width="1.5"/>`,
  iface: `<rect x="1.5" y="4.5" width="13" height="7" rx="1" ${S}/><path d="M4 7h1M6.5 7h1M9 7h1M11.5 7h1" ${S}/>`,
  export:
    `<path d="M3.5 6.5v8h9v-8" ${S}/><path d="M8 10.5V1.8M5 4.6 8 1.6l3 3" ${S}/>`,
  lock:
    '<rect x="3" y="7" width="10" height="7.5" rx="1.3" fill="#d9a520" stroke="#9a7212" stroke-width="1"/>' +
    `<path d="M5.3 7V5.2a2.7 2.7 0 0 1 5.4 0V7" ${S}/>`,
  graph:
    `<path d="M1.5 1.8v12.7h13" ${S}/>` +
    '<path d="M3.5 11.5 6.5 7l2.5 2.5 4.5-6" fill="none" stroke="#2e6fd8" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>',
  expert:
    '<path d="M8 1.6 15 14H1z" fill="#f7d774" stroke="#a88400" stroke-width="1" stroke-linejoin="round"/>' +
    '<path d="M8 6v4.2M8 11.8v.4" stroke="#3a2e00" stroke-width="1.5" stroke-linecap="round"/>',
} as const;

export type IconName = keyof typeof ICONS;

export function icon(name: IconName, cls = "icon"): SVGSVGElement {
  const wrap = document.createElement("span");
  wrap.innerHTML = `<svg class="${cls}" viewBox="0 0 16 16" width="16" height="16" aria-hidden="true" focusable="false">${ICONS[name]}</svg>`;
  return wrap.firstElementChild as SVGSVGElement;
}
