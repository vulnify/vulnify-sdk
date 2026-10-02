import type { AgentAction, Decision, LgpdCategory, ReviewStatus, RiskLevel, VulnifyDecision } from './index';
import type { Destination, PostEvent } from './contract';

type WithoutIndex<T> = {
  [K in keyof T as string extends K ? never : number extends K ? never : K]: T[K];
};
type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends <T>() => T extends B ? 1 : 2 ? true : false;
type Assert<T extends true> = T;

/**
 * Hand-written SDK types must match the generated event body.
 * `finalDecision` stays optional on the SDK. `id`, `riskLevel`, and `riskScore` are nullable
 * only for the fail-closed fallback. `degraded` is SDK-only.
 */
type SpecEvent = WithoutIndex<PostEvent>;
type SdkEvent = Omit<VulnifyDecision, 'degraded' | 'id' | 'riskLevel' | 'riskScore' | 'finalDecision'> & {
  id: string;
  riskLevel: RiskLevel;
  riskScore: number;
  finalDecision: Decision;
};
type FieldDiff<K extends keyof SpecEvent & keyof SdkEvent> = Equal<SpecEvent[K], SdkEvent[K]> extends true ? never : K;

type _eventFieldsMatch = Assert<
  Equal<
    | FieldDiff<'id'>
    | FieldDiff<'decision'>
    | FieldDiff<'finalDecision'>
    | FieldDiff<'evaluatedDecision'>
    | FieldDiff<'monitored'>
    | FieldDiff<'riskLevel'>
    | FieldDiff<'riskScore'>
    | FieldDiff<'reasons'>
    | FieldDiff<'policy'>
    | FieldDiff<'dlpFindings'>
    | FieldDiff<'lgpdCategories'>
    | FieldDiff<'review'>
    | FieldDiff<'quotaExceeded'>
    | FieldDiff<'sandbox'>
    | Exclude<keyof SpecEvent, keyof SdkEvent>
    | Exclude<keyof SdkEvent, keyof SpecEvent>,
    never
  >
>;

type _names = Assert<
  Equal<
    | (Equal<Decision, PostEvent['decision']> extends true ? never : 'decision')
    | (Equal<RiskLevel, PostEvent['riskLevel']> extends true ? never : 'riskLevel')
    | (Equal<LgpdCategory, PostEvent['lgpdCategories'][number]> extends true ? never : 'lgpd')
    | (Equal<ReviewStatus, NonNullable<PostEvent['review']>['status']> extends true ? never : 'reviewStatus')
    | (Equal<AgentAction['action'], import('./contract').IngestRequest['action']> extends true ? never : 'action')
    | (Equal<NonNullable<AgentAction['destination']>, Destination> extends true ? never : 'destination'),
    never
  >
>;
