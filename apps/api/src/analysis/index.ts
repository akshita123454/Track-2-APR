export { analyzeBlastRadius } from "./core/blast-radius.js";
export { classifyExposure } from "./core/exposure-ladder.js";
export {
  analyzeTyposquatCandidates,
} from "./typosquat/typosquat-analysis.js";

export type {
  AnalysisWarning,
  AnalysisWarningCode,
  AppliedBlastRadiusLimits,
  BlastRadiusOptions,
  BlastRadiusPath,
  BlastRadiusResult,
  BlastRadiusServiceCandidate,
  DependencyHop,
  ExposureAssessment,
  ExposureEvidenceSignals,
  ExposureStage,
  ReadonlyGraphReader,
  SecurityConclusion,
} from "./core/analysis-types.js";

export type {
  AppliedTyposquatAnalysisOptions,
  TyposquatAnalysisOptions,
  TyposquatAnalysisResult,
  TyposquatAnalysisWarning,
  TyposquatCandidate,
  TyposquatPackageRole,
  TyposquatSignal,
  TyposquatSignalCode,
  TyposquatWarningCode,
} from "./typosquat/typosquat-analysis.js";
