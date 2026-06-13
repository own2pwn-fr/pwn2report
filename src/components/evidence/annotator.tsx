import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Eraser, MousePointer, Pencil, Save, Square, Undo2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { errorMessage } from "@/lib/ipc";
import { canvasToPngBytes, objectUrlFromBytes } from "@/lib/image";
import {
  useAddEvidenceImage,
  useDeleteEvidenceImage,
  useEvidenceBytes,
} from "@/lib/queries/use-evidence";
import type { EvidenceImage } from "@/lib/types";

type Tool = "redact" | "box" | "arrow" | "pen";

interface Point {
  x: number;
  y: number;
}

// A single committed annotation, stored in NATURAL image coordinates so the
// final composite is resolution-independent of the on-screen display scale.
type Shape =
  | { type: "redact"; a: Point; b: Point }
  | { type: "box"; a: Point; b: Point; color: string }
  | { type: "arrow"; a: Point; b: Point; color: string }
  | { type: "pen"; points: Point[]; color: string };

const TOOLS: { id: Tool; icon: typeof Square }[] = [
  { id: "redact", icon: Eraser },
  { id: "box", icon: Square },
  { id: "arrow", icon: MousePointer },
  { id: "pen", icon: Pencil },
];

/** Stroke width scaled to the image so lines stay visible on large captures. */
function strokeWidth(canvas: HTMLCanvasElement): number {
  return Math.max(2, Math.round(Math.max(canvas.width, canvas.height) / 400));
}

function drawArrow(ctx: CanvasRenderingContext2D, a: Point, b: Point, width: number) {
  const head = Math.max(10, width * 4);
  const angle = Math.atan2(b.y - a.y, b.x - a.x);
  ctx.beginPath();
  ctx.moveTo(a.x, a.y);
  ctx.lineTo(b.x, b.y);
  ctx.stroke();
  ctx.beginPath();
  ctx.moveTo(b.x, b.y);
  ctx.lineTo(b.x - head * Math.cos(angle - Math.PI / 6), b.y - head * Math.sin(angle - Math.PI / 6));
  ctx.lineTo(b.x - head * Math.cos(angle + Math.PI / 6), b.y - head * Math.sin(angle + Math.PI / 6));
  ctx.closePath();
  ctx.fill();
}

function drawShape(ctx: CanvasRenderingContext2D, shape: Shape, width: number) {
  if (shape.type === "redact") {
    ctx.fillStyle = "#000000";
    const x = Math.min(shape.a.x, shape.b.x);
    const y = Math.min(shape.a.y, shape.b.y);
    ctx.fillRect(x, y, Math.abs(shape.b.x - shape.a.x), Math.abs(shape.b.y - shape.a.y));
    return;
  }
  ctx.strokeStyle = shape.color;
  ctx.fillStyle = shape.color;
  ctx.lineWidth = width;
  ctx.lineJoin = "round";
  ctx.lineCap = "round";
  if (shape.type === "box") {
    const x = Math.min(shape.a.x, shape.b.x);
    const y = Math.min(shape.a.y, shape.b.y);
    ctx.strokeRect(x, y, Math.abs(shape.b.x - shape.a.x), Math.abs(shape.b.y - shape.a.y));
  } else if (shape.type === "arrow") {
    drawArrow(ctx, shape.a, shape.b, width);
  } else {
    ctx.beginPath();
    shape.points.forEach((p, i) => (i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y)));
    ctx.stroke();
  }
}

export function Annotator({
  open,
  onOpenChange,
  source,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  source: EvidenceImage;
}) {
  const { t } = useTranslation();
  const { data: bytes } = useEvidenceBytes(source.id);
  const addImage = useAddEvidenceImage(source.finding_id);
  const deleteImage = useDeleteEvidenceImage(source.finding_id);

  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const imageRef = useRef<HTMLImageElement | null>(null);
  const shapesRef = useRef<Shape[]>([]);
  const draftRef = useRef<Shape | null>(null);
  const drawingRef = useRef(false);

  const [tool, setTool] = useState<Tool>("redact");
  const [color, setColor] = useState("#ef4444");
  const [ready, setReady] = useState(false);
  // Bump to force a re-render (e.g. after undo/clear) without storing shapes in state.
  const [, setTick] = useState(0);
  const rerender = () => setTick((n) => n + 1);

  // Repaint the whole canvas: base image + all committed shapes + the draft.
  const repaint = useCallback(() => {
    const canvas = canvasRef.current;
    const img = imageRef.current;
    if (!canvas || !img) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    const w = strokeWidth(canvas);
    for (const s of shapesRef.current) drawShape(ctx, s, w);
    if (draftRef.current) drawShape(ctx, draftRef.current, w);
  }, []);

  // Load the source bytes into an <img>, size the canvas to natural pixels.
  useEffect(() => {
    if (!open || !bytes) return;
    setReady(false);
    shapesRef.current = [];
    draftRef.current = null;
    const url = objectUrlFromBytes(bytes, source.mime);
    const img = new Image();
    img.onload = () => {
      imageRef.current = img;
      const canvas = canvasRef.current;
      if (canvas) {
        canvas.width = img.naturalWidth || img.width;
        canvas.height = img.naturalHeight || img.height;
      }
      setReady(true);
      repaint();
    };
    img.src = url;
    return () => URL.revokeObjectURL(url);
  }, [open, bytes, source.mime, repaint]);

  // Map a pointer event to natural image coordinates.
  const toImagePoint = (e: React.PointerEvent<HTMLCanvasElement>): Point => {
    const canvas = canvasRef.current!;
    const rect = canvas.getBoundingClientRect();
    return {
      x: ((e.clientX - rect.left) / rect.width) * canvas.width,
      y: ((e.clientY - rect.top) / rect.height) * canvas.height,
    };
  };

  const onPointerDown = (e: React.PointerEvent<HTMLCanvasElement>) => {
    if (!ready) return;
    e.currentTarget.setPointerCapture(e.pointerId);
    drawingRef.current = true;
    const p = toImagePoint(e);
    if (tool === "pen") draftRef.current = { type: "pen", points: [p], color };
    else if (tool === "redact") draftRef.current = { type: "redact", a: p, b: p };
    else draftRef.current = { type: tool, a: p, b: p, color };
    repaint();
  };

  const onPointerMove = (e: React.PointerEvent<HTMLCanvasElement>) => {
    if (!drawingRef.current || !draftRef.current) return;
    const p = toImagePoint(e);
    const d = draftRef.current;
    if (d.type === "pen") d.points.push(p);
    else d.b = p;
    repaint();
  };

  const onPointerUp = () => {
    if (!drawingRef.current) return;
    drawingRef.current = false;
    const d = draftRef.current;
    draftRef.current = null;
    if (d) {
      // Drop zero-area shapes (a click without a drag).
      const trivial =
        d.type !== "pen" && d.a.x === d.b.x && d.a.y === d.b.y;
      const emptyPen = d.type === "pen" && d.points.length < 2;
      if (!trivial && !emptyPen) {
        shapesRef.current = [...shapesRef.current, d];
        rerender();
      }
    }
    repaint();
  };

  const undo = () => {
    shapesRef.current = shapesRef.current.slice(0, -1);
    rerender();
    repaint();
  };

  const clear = () => {
    shapesRef.current = [];
    rerender();
    repaint();
  };

  const handleSave = async () => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    // Force a clean composite (no in-progress draft) before exporting.
    draftRef.current = null;
    repaint();
    try {
      const data = await canvasToPngBytes(canvas);
      // Add the flattened (redacted/annotated) image FIRST. The canvas export
      // already drops any source metadata, and redactions are baked into the
      // pixels here.
      await addImage.mutateAsync({
        caption: source.caption,
        mime: "image/png",
        data,
      });
      // Only after the redacted version is safely persisted do we destroy the
      // un-redacted original, so a redaction is truly destructive end-to-end:
      // the secret no longer exists in the vault, exports or sync bundles. If
      // this delete fails the user keeps both copies (worst case = a leftover
      // original) rather than losing the new one.
      try {
        await deleteImage.mutateAsync(source.id);
      } catch (delErr) {
        toast.error(errorMessage(delErr, "annotator.deleteOriginalError"));
      }
      onOpenChange(false);
    } catch (err) {
      toast.error(errorMessage(err, "annotator.saveError"));
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] max-w-4xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{t("annotator.title")}</DialogTitle>
          <DialogDescription>{t("annotator.replaceHint")}</DialogDescription>
        </DialogHeader>

        <div className="flex flex-wrap items-center gap-3 rounded-lg border p-2">
          <div className="flex items-center gap-1">
            {TOOLS.map(({ id, icon: Icon }) => (
              <Button
                key={id}
                type="button"
                size="sm"
                variant={tool === id ? "brand" : "outline"}
                onClick={() => setTool(id)}
                title={t(`annotator.tools.${id}`)}
              >
                <Icon />
                {t(`annotator.tools.${id}`)}
              </Button>
            ))}
          </div>
          <div className="flex items-center gap-2">
            <Label htmlFor="annot-color" className="text-xs text-muted-foreground">
              {t("annotator.color")}
            </Label>
            <input
              id="annot-color"
              type="color"
              value={color}
              disabled={tool === "redact"}
              onChange={(e) => setColor(e.target.value)}
              className="h-8 w-10 cursor-pointer rounded border bg-transparent disabled:opacity-40"
            />
          </div>
          <div className="ml-auto flex items-center gap-1">
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={undo}
              disabled={shapesRef.current.length === 0}
            >
              <Undo2 />
              {t("annotator.undo")}
            </Button>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={clear}
              disabled={shapesRef.current.length === 0}
            >
              {t("annotator.clear")}
            </Button>
          </div>
        </div>

        <div className="flex max-h-[55vh] justify-center overflow-auto rounded-lg border bg-muted/30 p-2">
          <canvas
            ref={canvasRef}
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            className="max-w-full touch-none"
            style={{ height: "auto", cursor: ready ? "crosshair" : "wait" }}
          />
        </div>

        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
            {t("common.cancel")}
          </Button>
          <Button
            type="button"
            variant="brand"
            onClick={() => void handleSave()}
            disabled={addImage.isPending || deleteImage.isPending}
          >
            <Save />
            {addImage.isPending || deleteImage.isPending
              ? t("annotator.saving")
              : t("annotator.save")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
