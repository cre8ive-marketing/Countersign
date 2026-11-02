import { useEffect, useId, useRef, useState } from 'react';
import { apiFetch } from '../lib/client';

// An input that suggests saved contacts as you type (ARIA 1.2 combobox + listbox). onPick gets { id, name, email }.
export default function ContactInput({ value, onChange, onPick, ...props }) {
  const id = useId();
  const listId = `${id}-list`;
  const [items, setItems] = useState([]);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const typed = useRef(false); // search only after typing, not on mount or after a pick fills the value

  useEffect(() => {
    if (!typed.current) return;
    const q = value.trim();
    if (q.length < 2) { setItems([]); setOpen(false); return; }
    let live = true;
    const t = setTimeout(() => {
      apiFetch(`/api/contacts?q=${encodeURIComponent(q)}&limit=8`, { method: 'GET' })
        .then(({ contacts = [] }) => { if (live) { setItems(contacts); setOpen(contacts.length > 0); setActive(-1); } })
        .catch(() => { if (live) { setItems([]); setOpen(false); } }); // suggestions are optional; typing still works
    }, 250);
    return () => { live = false; clearTimeout(t); };
  }, [value]);

  function pick(c) {
    typed.current = false;
    setOpen(false);
    setItems([]);
    onPick(c);
  }

  function onKeyDown(e) {
    if (e.key === 'ArrowDown' && items.length) {
      e.preventDefault();
      setOpen(true);
      setActive((a) => (a + 1) % items.length);
    } else if (e.key === 'ArrowUp' && open) {
      e.preventDefault();
      setActive((a) => (a <= 0 ? items.length - 1 : a - 1));
    } else if (e.key === 'Enter' && open && active >= 0) {
      e.preventDefault();
      pick(items[active]);
    } else if (e.key === 'Escape' && open) {
      e.preventDefault();
      setOpen(false);
    }
  }

  return (
    <div className="combo">
      <input {...props} value={value} role="combobox" aria-autocomplete="list" aria-expanded={open} aria-controls={listId}
        aria-activedescendant={open && active >= 0 ? `${id}-${active}` : undefined} autoComplete="off"
        onChange={(e) => { typed.current = true; onChange(e); }} onKeyDown={onKeyDown} onBlur={() => setOpen(false)} />
      <ul id={listId} role="listbox" className="combo-list" aria-label="Saved contacts" hidden={!open}>
        {items.map((c, i) => (
          <li key={c.id} id={`${id}-${i}`} role="option" aria-selected={i === active} className={i === active ? 'is-active' : undefined}
            onMouseDown={(e) => e.preventDefault()} onMouseEnter={() => setActive(i)} onClick={() => pick(c)}>
            <strong>{c.name}</strong><span>{c.email}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
