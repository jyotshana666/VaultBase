import React from 'react';

export function Badge({ variant, children, isCurrent }) {
  let badgeClass = 'badge ';

  switch ((variant || '').toUpperCase()) {
    case 'LOW':
    case 'TRUSTED':
    case 'ACTIVE':
      badgeClass += 'badge-low';
      break;
    case 'MEDIUM':
    case 'NEW':
      badgeClass += 'badge-medium';
      break;
    case 'HIGH':
      badgeClass += 'badge-high';
      break;
    case 'CRITICAL':
    case 'REVOKED':
    case 'EXPIRED':
      badgeClass += 'badge-critical';
      break;
    default:
      badgeClass += 'badge-medium';
  }

  return (
    <span className={badgeClass}>
      {isCurrent && <span style={{ color: '#818cf8', marginRight: 4 }}>●</span>}
      {children || variant}
    </span>
  );
}
