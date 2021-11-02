/** Http headers collection. */
export declare class Headers {
    entries: [string, string][];
    constructor(headers: Record<string, string>);
    /** Returns header names in consistent order matching `.entries`. */
    names(): string[];
    /** Throws if there are any duplicate headers with different casing. */
    validated(): this;
    /** Retain headers in `tlHeaders` using the exact name casing in `tlHeaders`
     *  and sort entries to match the order of `tlHeaders`.
     */
    retainAndSort(tlHeaders: string[]): void;
}
