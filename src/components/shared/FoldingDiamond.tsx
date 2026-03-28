import type { CSSProperties } from 'react';

const STYLES = `
@keyframes diamond-face1 {
  0%        { transform: perspective(140px) rotateX(-180deg); opacity: 0; }
  8%, 68%   { transform: perspective(140px) rotateX(0deg); opacity: 1; }
  70%       { transform: perspective(140px) rotateX(0deg); opacity: 0.6; }
  88%, 100% { transform: perspective(140px) rotateX(0deg); opacity: 0; }
}
@keyframes diamond-face2 {
  0%, 15%   { transform: perspective(140px) rotateY(180deg); opacity: 0; }
  23%, 70%  { transform: perspective(140px) rotateY(0deg); opacity: 1; }
  75%       { transform: perspective(140px) rotateY(0deg); opacity: 0.6; }
  90%, 100% { transform: perspective(140px) rotateY(0deg); opacity: 0; }
}
@keyframes diamond-face3 {
  0%, 30%   { transform: perspective(140px) rotateX(180deg); opacity: 0; }
  38%, 72%  { transform: perspective(140px) rotateX(0deg); opacity: 1; }
  78%       { transform: perspective(140px) rotateX(0deg); opacity: 0.6; }
  92%, 100% { transform: perspective(140px) rotateX(0deg); opacity: 0; }
}
@keyframes diamond-face4 {
  0%, 45%   { transform: perspective(140px) rotateY(-180deg); opacity: 0; }
  53%, 74%  { transform: perspective(140px) rotateY(0deg); opacity: 1; }
  80%       { transform: perspective(140px) rotateY(0deg); opacity: 0.6; }
  94%, 100% { transform: perspective(140px) rotateY(0deg); opacity: 0; }
}
`;

const DURATION = '2.5s';
const EASING = 'ease-in-out';

let stylesInjected = false;

export function FoldingDiamond({ size = 40, color = '#C4A87D' }: { size?: number; color?: string }) {
  if (!stylesInjected && typeof document !== 'undefined') {
    const style = document.createElement('style');
    style.textContent = STYLES;
    document.head.appendChild(style);
    stylesInjected = true;
  }

  const faceBase: CSSProperties = {
    width: '50%',
    height: '50%',
    position: 'absolute',
    backgroundColor: color,
  };

  return (
    <div style={{ width: size, height: size, position: 'relative', transform: 'rotate(45deg)' }}>
      <div style={{ ...faceBase, top: 0, left: 0, transformOrigin: 'bottom right', animation: `diamond-face1 ${DURATION} ${EASING} infinite` }} />
      <div style={{ ...faceBase, top: 0, right: 0, transformOrigin: 'bottom left', animation: `diamond-face2 ${DURATION} ${EASING} infinite` }} />
      <div style={{ ...faceBase, bottom: 0, right: 0, transformOrigin: 'top left', animation: `diamond-face3 ${DURATION} ${EASING} infinite` }} />
      <div style={{ ...faceBase, bottom: 0, left: 0, transformOrigin: 'top right', animation: `diamond-face4 ${DURATION} ${EASING} infinite` }} />
    </div>
  );
}

export function DiamondLoader({ text }: { text?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-12" role="status" aria-label="Loading">
      <FoldingDiamond size={44} />
      {text && <span className="text-sm text-[var(--text-secondary)]">{text}</span>}
    </div>
  );
}
