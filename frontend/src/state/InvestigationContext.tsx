import { createContext, useContext } from "react";
import type { Investigation } from "../types";

interface Ctx {
  investigation: Investigation | null;
  setInvestigation: (inv: Investigation | null) => void;
}

export const InvestigationContext = createContext<Ctx>({
  investigation: null,
  setInvestigation: () => {},
});

export function useInvestigation() {
  return useContext(InvestigationContext);
}
