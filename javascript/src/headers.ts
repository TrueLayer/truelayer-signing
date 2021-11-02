/** Http headers collection. */
export class Headers {

  public entries: [string, string][];

  constructor(headers: Record<string, string>) {
    this.entries = Object.entries(headers);
  }

  /** Returns header names in consistent order matching `.entries`. */
  names() {
    return this.entries.map(entry => entry[0]);
  }

  /** Throws if there are any duplicate headers with different casing. */
  validated() {
    const names = this.names();
    const distinctNames = new Set(names.map(n => n.toLowerCase()));

    if (names.length !== distinctNames.size) {
      throw new Error("duplicate header names with different casing")
    }

    return this;
  }

  /** Retain headers in `tlHeaders` using the exact name casing in `tlHeaders`
   *  and sort entries to match the order of `tlHeaders`.
   */
  retainAndSort(tlHeaders: string[]) {
    let all = new Map<string, string>();

    for (const [name, value] of this.entries) {
      all.set(name.toLowerCase(), value);
    }

    this.entries = tlHeaders.map(name => [name, all.get(name.toLowerCase()) || ""]);
  }
}
