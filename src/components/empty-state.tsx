import { motion } from "motion/react";
import type { LucideIcon } from "lucide-react";
import { Button } from "@/components/ui/button";

export function EmptyState({
  icon: Icon,
  title,
  body,
  ctaLabel,
  onCta,
}: {
  icon: LucideIcon;
  title: string;
  body: string;
  ctaLabel?: string;
  onCta?: () => void;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col items-center justify-center gap-4 rounded-lg border border-dashed p-12 text-center"
    >
      <div
        className="flex size-14 items-center justify-center rounded-full"
        style={{ backgroundColor: "hsl(var(--accent-brand) / 0.12)" }}
      >
        <Icon className="size-6 text-accent-brand" />
      </div>
      <div className="space-y-1.5">
        <h3 className="text-lg font-semibold">{title}</h3>
        <p className="max-w-sm text-sm text-muted-foreground">{body}</p>
      </div>
      {ctaLabel && onCta && (
        <Button variant="brand" onClick={onCta}>
          {ctaLabel}
        </Button>
      )}
    </motion.div>
  );
}
