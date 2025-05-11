export function getPlaceholderImage(width = 600, height = 400, text = '', id = '') {
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');

  // Fill background
  ctx.fillStyle = '#f3f4f6';
  ctx.fillRect(0, 0, width, height);

  // Add text
  ctx.fillStyle = '#9ca3af';
  ctx.font = '24px Arial';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(text || 'News Image', width / 2, height / 2);

  // Add ID if provided
  if (id) {
    ctx.font = '16px Arial';
    ctx.fillText(`ID: ${id}`, width / 2, height / 2 + 30);
  }

  return canvas.toDataURL();
} 