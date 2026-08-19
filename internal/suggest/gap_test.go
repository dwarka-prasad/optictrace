package suggest

import "testing"

// A card number reached as `card.number` is the single most important field in
// the table, and it was being missed: the heuristic matched `card_number` but
// not the `card: { number: ... }` shape every payment API actually uses.
func TestNestedCardAndAccountNumbers(t *testing.T) {
	for _, name := range []string{
		"card.number", "payment.card.number", "card.no", "credit_card.number",
		"account.number", "bank_account.no",
	} {
		c, ok := ClassifyField(name)
		if !ok {
			t.Errorf("%q should be classified sensitive", name)
			continue
		}
		if c.Confidence != High {
			t.Errorf("%q classified %s; a PAN or bank account is high confidence", name, c.Confidence)
		}
	}
}

// The reason this is a PAIR match and not a rule on `number`: a heuristic that
// flags every number field gets muted, and a muted heuristic protects nothing.
func TestOrdinaryNumbersAreNotFlagged(t *testing.T) {
	for _, name := range []string{
		"order.number", "page.number", "invoice.number", "number",
		"line.no", "seat.num", "building.number",
	} {
		if _, ok := ClassifyField(name); ok {
			t.Errorf("%q was flagged; over-flagging is how a heuristic gets turned off", name)
		}
	}
}
