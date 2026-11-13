/**
 * The questions the user asked the agent this session, for the page to show
 * whether they were answered. They live in the view's state; the functions
 * here work out its next value, as those of edits.ts do for the marks.
 */

import { printable } from "./text.ts";
import type { Question } from "../shared/api.ts";

/** Questions kept: the newest. */
export const MAX_QUESTIONS = 20;
/** Characters of a question the state keeps; the agent gets it in full. */
export const MAX_QUESTION_SHOWN = 300;
/** Characters of an answer. */
export const MAX_ANSWER = 600;

/** `text` cut to `max` characters, with "…" where it was. */
function cut(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

/** `questions` with `q` after them; the oldest go once there are more than MAX_QUESTIONS. */
export function withQuestion(questions: readonly Question[], q: Omit<Question, "answer">): Question[] {
  return [...questions, { ...q, text: cut(q.text, MAX_QUESTION_SHOWN), answer: null }].slice(-MAX_QUESTIONS);
}

/** The question `id` names, else the oldest without an answer; refused when it is none of them. */
export function openQuestion(questions: readonly Question[], id?: number): Question {
  if (id !== undefined) {
    const q = questions.find((x) => x.id === id);
    if (!q) throw new Error(`there is no question ${id} (the last ${MAX_QUESTIONS} are kept)`);
    if (q.answer) throw new Error(`question ${id} is answered already`);
    return q;
  }
  const q = questions.find((x) => !x.answer);
  if (!q) throw new Error("no question is waiting for an answer");
  return q;
}

/** `questions` with `question` answered `text` at `at`. */
export function answered(questions: readonly Question[], question: Question, text: string, at: number): Question[] {
  const answer = printable(text.replace(/\s+/g, " ").trim()).slice(0, MAX_ANSWER);
  if (!answer) throw new Error("the answer is empty");
  return questions.map((q) => (q === question ? { ...q, answer: { text: answer, at } } : q));
}

/** Questions without an answer. */
export function openQuestions(questions: readonly Question[]): Question[] {
  return questions.filter((q) => !q.answer);
}

/** The subject of a question as the agent is told: "frame 12", "3 packets", "" for none. */
export function aboutText(frame: number | null, count: number): string {
  return count <= 0 || frame === null ? "" : count === 1 ? `frame ${frame}` : `${count} packets`;
}
