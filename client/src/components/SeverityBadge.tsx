import type { IncidentRecord } from "../types";
import { Badge } from "@/components/ui/badge";
import type { BadgeProps } from "@/components/ui/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { HelpCircle } from "lucide-react";

interface Props {
  severity: IncidentRecord["overall_severity"];
  className?: string;
  showIcon?: boolean;
}

const VARIANT_MAP: Record<string, BadgeProps["variant"]> = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
};

const SEVERITY_INFO: Record<string, string> = {
  LOW: "Reconnaissance or harmless listing of resources.",
  MEDIUM: "Read access to data or communication usage.",
  HIGH: "Creation of persistent resources or minor financial abuse.",
  CRITICAL: "Data exfiltration, privilege escalation, or code compromise.",
};

const SeverityBadge: React.FC<Props> = ({
  severity,
  className,
  showIcon = true,
}) => {
  if (!severity) return null;

  const content = (
    <Badge variant={VARIANT_MAP[severity] ?? "outline"} className={className}>
      {severity}
      {showIcon && (
        <span className="ml-1 opacity-70 hover:opacity-100">
          <HelpCircle size={12} />
        </span>
      )}
    </Badge>
  );

  if (!showIcon) return content;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex cursor-help">{content}</span>
      </TooltipTrigger>
      <TooltipContent>
        <p className="max-w-xs">
          {SEVERITY_INFO[severity] || "Severity level"}
        </p>
      </TooltipContent>
    </Tooltip>
  );
};

export default SeverityBadge;
