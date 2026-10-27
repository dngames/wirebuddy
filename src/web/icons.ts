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
  // WireBuddy's own mark; "wireshark" below is only for Open in Wireshark
  logo:
    '<path d="M3.5 1.5h9a2.5 2.5 0 0 1 2.5 2.5v5.5a2.5 2.5 0 0 1-2.5 2.5H7.5L4 14.8V12h-.5A2.5 2.5 0 0 1 1 9.5V4a2.5 2.5 0 0 1 2.5-2.5z" fill="#0f9d8f"/>' +
    '<path d="M3 7h1.8l1.1-2.6 1.6 5.2 1.6-5.2 1.1 2.6H13" fill="none" stroke="#fff" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/>',
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
  restart:
    '<path d="M3 14c2.9-1.2 5.2-4 5.9-8.4 1.6 2.5 2.8 5.3 3.3 8.4z" fill="#3a9a3a"/>' +
    '<path d="M2.4 7.4A5.6 5.6 0 0 1 12.6 3.4" fill="none" stroke="#3a9a3a" stroke-width="1.4" stroke-linecap="round"/>' +
    '<path d="M13.4 1.2v2.9h-2.9" fill="none" stroke="#3a9a3a" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/>',
  gear:
    '<path d="M8 1.2v2.4M8 12.4v2.4M1.2 8h2.4M12.4 8h2.4M3.2 3.2l1.7 1.7M11.1 11.1l1.7 1.7M3.2 12.8l1.7-1.7M11.1 4.9l1.7-1.7" stroke="currentColor" stroke-width="2.1"/>' +
    '<circle cx="8" cy="8" r="4.2" fill="none" stroke="currentColor" stroke-width="1.6"/>' +
    `<circle cx="8" cy="8" r="1.5" ${S}/>`,
  save: `<path d="M2.5 2.5h9l2 2v9h-11z" ${S}/><path d="M5 2.5v3.3h5.5V2.5M4.8 13.5V9.2h6.4v4.3" ${S}/>`,
  find: `<circle cx="6.7" cy="6.7" r="4.4" ${S}/><path d="M10 10l4.3 4.3" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"/>`,
  previous: `<path d="M10 3 5 8l5 5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>`,
  next: `<path d="M6 3l5 5-5 5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>`,
  layout: `<rect x="1.5" y="2.5" width="13" height="11" rx="1" ${S}/><path d="M1.5 6.5h13M1.5 10h13M8 6.5v7" ${S}/>`,
  first: `<path d="M2.8 3v10M13.5 8H5M8.8 4.3 5 8l3.8 3.7" ${S}/>`,
  last: `<path d="M13.2 3v10M2.5 8H11M7.2 4.3 11 8l-3.8 3.7" ${S}/>`,
  colorize:
    '<rect x="1.5" y="2" width="13" height="3.4" rx=".6" fill="#a7c7ff"/><rect x="1.5" y="6.3" width="13" height="3.4" rx=".6" fill="#ffd28a"/>' +
    '<rect x="1.5" y="10.6" width="13" height="3.4" rx=".6" fill="#b9e6a3"/>',
  zoomIn:
    `<circle cx="6.7" cy="6.7" r="4.6" ${S}/><path d="M10.1 10.1l4.2 4.2" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"/>` +
    `<path d="M4.5 6.7h4.4M6.7 4.5v4.4" ${S}/>`,
  zoomOut:
    `<circle cx="6.7" cy="6.7" r="4.6" ${S}/><path d="M10.1 10.1l4.2 4.2" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"/>` +
    `<path d="M4.5 6.7h4.4" ${S}/>`,
  zoomNormal:
    `<circle cx="6.7" cy="6.7" r="4.6" ${S}/><path d="M10.1 10.1l4.2 4.2" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"/>` +
    `<path d="M5.7 5.3 7 4.4v4.8" ${S}/>`,
  resize: `<path d="M1.8 2.5v11M14.2 2.5v11" ${S}/><path d="M4.3 8h7.4M6.3 6 4.3 8l2 2M9.7 6l2 2-2 2" ${S}/>`,
} as const;

export type IconName = keyof typeof ICONS;

export function icon(name: IconName, cls = "icon"): SVGSVGElement {
  const wrap = document.createElement("span");
  wrap.innerHTML = `<svg class="${cls}" viewBox="0 0 16 16" width="16" height="16" aria-hidden="true" focusable="false">${ICONS[name]}</svg>`;
  return wrap.firstElementChild as SVGSVGElement;
}
