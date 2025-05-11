const BACKUP_KEY = 'news_backup';

// Save articles for a key (category or search)
export function saveNewsBackup(key, articles) {
  let backup = {};
  try {
    backup = JSON.parse(localStorage.getItem(BACKUP_KEY)) || {};
  } catch {}
  backup[key] = articles;
  localStorage.setItem(BACKUP_KEY, JSON.stringify(backup));
}

// Load articles for a key
export function loadNewsBackup(key) {
  try {
    const backup = JSON.parse(localStorage.getItem(BACKUP_KEY)) || {};
    return backup[key] || [];
  } catch {
    return [];
  }
} 