/** A request whose view (file, filter or list) changed while it ran, or that was made against one that has gone. */
export class StaleGenerationError extends Error {}
