import { AttrPairEqual } from "./AttrPairEqual.mjs";

/**
 * @deprecated Use {@link AttrPairEqual}. Scheduled for removal in a future major version.
 */
export const AttrMatchRule = AttrPairEqual;
export type AttrMatchRuleConfig = ConstructorParameters<typeof AttrPairEqual>[0];
