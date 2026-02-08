/**
 * Toggle - Accessible toggle switch component (w-11 h-6).
 */

interface ToggleProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
}

const trackStyle =
  "w-11 h-6 bg-red-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-blue-500 rounded-full peer peer-checked:after:translate-x-full rtl:peer-checked:after:-translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:start-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600 peer-disabled:opacity-50";

export function Toggle({ checked, onChange, disabled }: ToggleProps): React.ReactElement {
  return (
    <div className="relative">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        disabled={disabled}
        className="sr-only peer"
        role="switch"
        aria-checked={checked}
      />
      <div className={trackStyle} />
    </div>
  );
}
