import { useState, type ReactNode } from "react";
import { AnimatePresence, motion } from "motion/react";
import { ChevronDown } from "lucide-react";
import { Card } from "@/components/ui/card";
import { cn } from "@/lib/utils";

/**
 * A titled card whose body can be collapsed. Used to group the report-detail
 * sections (Details / Scope / Assets / Findings) so the page stays readable
 * without pulling in a full tabs dependency.
 */
export function CollapsibleSection({
  title,
  icon: Icon,
  count,
  defaultOpen = true,
  actions,
  children,
  className,
}: {
  title: string;
  icon?: React.ComponentType<{ className?: string }>;
  /** Optional badge-like count shown next to the title. */
  count?: number;
  defaultOpen?: boolean;
  /** Optional controls rendered on the right of the header (do not toggle). */
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <Card className={cn("overflow-hidden", className)}>
      <div className="flex items-center justify-between gap-3 p-5">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          aria-expanded={open}
          className="flex flex-1 items-center gap-2 text-left"
        >
          <ChevronDown
            className={cn(
              "size-4 text-muted-foreground transition-transform",
              open ? "rotate-0" : "-rotate-90",
            )}
          />
          {Icon && <Icon className="size-4 text-muted-foreground" />}
          <span className="text-base font-semibold tracking-tight">{title}</span>
          {typeof count === "number" && (
            <span className="rounded-full bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground">
              {count}
            </span>
          )}
        </button>
        {actions && <div className="flex items-center gap-2">{actions}</div>}
      </div>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            key="content"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
          >
            <div className="px-5 pb-5">{children}</div>
          </motion.div>
        )}
      </AnimatePresence>
    </Card>
  );
}
