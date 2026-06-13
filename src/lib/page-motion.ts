import type { Variants, Transition } from "motion/react";

/**
 * Shared page transition variants used by every routed page so the AppShell's
 * <AnimatePresence mode="wait"> exit animation fires consistently. With
 * MotionConfig reducedMotion="user", these collapse to opacity-only for users
 * who prefer reduced motion.
 */
export const pageVariants: Variants = {
  initial: { opacity: 0, y: 8 },
  animate: { opacity: 1, y: 0 },
  exit: { opacity: 0, y: -8 },
};

export const pageTransition: Transition = { duration: 0.18, ease: "easeOut" };
