import type { CodeContext, Hit, Rule } from "../../engine/types.js";
import { evidence } from "../../engine/redact.js";
import { isCommentLine } from "../taint.js";

const USER_FILENAME_RE = /\b(?:originalname|originalFilename|original_filename)\b|\b(?:file|upload|f|uploaded_file|uploaded|image|photo|avatar|attachment)\.(?:filename|name)\b/;
const SAFE_NAME_RE = /secure_filename|randomUUID|uuid|nanoid|crypto\.random|token_hex|path\.basename\([^)]*\)\s*\.replace|sanitize[-_]?filename|slugify/i;
const PATH_SINK_RE = /path\.(?:join|resolve)\s*\(|os\.path\.join\s*\(|\.save\s*\(|\.mv\s*\(|writeFile(?:Sync)?\s*\(|createWriteStream\s*\(|\bopen\s*\(|Path\s*\(|\/["'`]\s*\+\s*[\w.]*(?:filename|originalname|name)\b|\/\$\{|\bcb\s*\(\s*null\s*,/;

export const codeUpload: Rule<CodeContext> = {
  id: "CODE-UPLOAD-001",
  title: "File upload without size/type limits or with a user-controlled path",
  severity: "high",
  confidence: "medium",
  evidenceKind: "static",
  lab: "lab-09-upload",
  pattern: "file-uploads",
  why:
    "Upload handlers that accept any file of any size let users fill the disk, upload HTML or scripts that are later served from your domain, or overwrite files when the client-supplied filename contains ../ path segments.",
  fix:
    "Set a maximum size (multer limits.fileSize, Flask MAX_CONTENT_LENGTH), allow only the types you need by checking the extension and the file's content, generate the stored filename yourself (a UUID), keep uploads outside the web root or in object storage, and serve them with a safe Content-Type and Content-Disposition: attachment.",
  method:
    "Flags multer configured without limits or without fileFilter; Flask/Werkzeug code that reads request.files with no MAX_CONTENT_LENGTH and no extension allowlist; and any path built from the client-supplied filename (originalname, file.filename) without secure_filename, a generated UUID name, or a sanitizer.",
  check(ctx) {
    const hits: Hit[] = [];
    const code = ctx.code;
    ctx.lines.forEach((line, i) => {
      if (isCommentLine(line)) return;
      if (/\bmulter\s*\(/.test(line)) {
        const missing: string[] = [];
        if (!/\blimits\s*:/.test(code)) missing.push("no size limit (limits.fileSize)");
        if (!/\bfileFilter\s*[:(]/.test(code)) missing.push("no type check (fileFilter)");
        if (missing.length) hits.push({ evidence: evidence(line), location: { line: i + 1 }, fixDetail: `Missing: ${missing.join(", ")}.` });
        return;
      }
      if (USER_FILENAME_RE.test(line) && PATH_SINK_RE.test(line) && !SAFE_NAME_RE.test(line)) {
        hits.push({
          evidence: evidence(line),
          location: { line: i + 1 },
          confidence: "high",
          fixDetail: "The stored path uses the client-supplied filename, which can contain ../ segments.",
        });
        return;
      }
    });
    const flaskFile = ctx.lines.findIndex((l) => /request\.files\s*[\[.]/.test(l));
    if (flaskFile >= 0 && !/MAX_CONTENT_LENGTH/.test(code) && !/ALLOWED_EXTENSIONS|allowed_file\s*\(|\.endswith\s*\(\s*\(|splitext|mimetypes|imghdr|filetype\.|magic\./.test(code)) {
      hits.push({
        evidence: evidence(ctx.lines[flaskFile]),
        location: { line: flaskFile + 1 },
        confidence: "medium",
        fixDetail: "Missing: MAX_CONTENT_LENGTH and an extension allowlist.",
      });
    }
    return hits;
  },
};
