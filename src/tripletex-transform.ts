/**
 * Maps MCP tool payloads to Tripletex v2 JSON bodies (PRD §5.1).
 */

export type OrderLineInput = {
  description?: string;
  count?: number;
  unitPriceExcludingVatCurrency?: number;
  unitPriceIncludingVatCurrency?: number;
  vatTypeId?: number;
  productId?: number;
  discount?: number;
};

export function transformOrderLine(line: OrderLineInput): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (line.description !== undefined) out.description = line.description;
  if (line.count !== undefined) out.count = line.count;
  if (line.unitPriceExcludingVatCurrency !== undefined) {
    out.unitPriceExcludingVatCurrency = line.unitPriceExcludingVatCurrency;
  }
  if (line.unitPriceIncludingVatCurrency !== undefined) {
    out.unitPriceIncludingVatCurrency = line.unitPriceIncludingVatCurrency;
  }
  if (line.vatTypeId !== undefined) out.vatType = { id: line.vatTypeId };
  if (line.productId !== undefined) out.product = { id: line.productId };
  if (line.discount !== undefined) out.discount = line.discount;
  return out;
}

export type CreateOrderInput = {
  customerId: number;
  orderDate: string;
  deliveryDate: string;
  orderLines?: OrderLineInput[];
  isPrioritizeAmountsIncludingVat?: boolean;
  currencyId?: number;
  ourReference?: string;
  yourReference?: string;
  invoiceComment?: string;
  receiverEmail?: string;
  invoicesDueIn?: number;
  departmentId?: number;
  projectId?: number;
};

export function buildOrderBody(input: CreateOrderInput): Record<string, unknown> {
  const body: Record<string, unknown> = {
    customer: { id: input.customerId },
    orderDate: input.orderDate,
    deliveryDate: input.deliveryDate,
  };
  if (input.orderLines !== undefined && input.orderLines.length > 0) {
    body.orderLines = input.orderLines.map(transformOrderLine);
  }
  if (input.isPrioritizeAmountsIncludingVat !== undefined) {
    body.isPrioritizeAmountsIncludingVat = input.isPrioritizeAmountsIncludingVat;
  }
  if (input.currencyId !== undefined) body.currency = { id: input.currencyId };
  if (input.ourReference !== undefined) body.ourReference = input.ourReference;
  if (input.yourReference !== undefined) body.yourReference = input.yourReference;
  if (input.invoiceComment !== undefined) body.invoiceComment = input.invoiceComment;
  if (input.receiverEmail !== undefined) body.receiverEmail = input.receiverEmail;
  if (input.invoicesDueIn !== undefined) body.invoicesDueIn = input.invoicesDueIn;
  if (input.departmentId !== undefined) body.department = { id: input.departmentId };
  if (input.projectId !== undefined) body.project = { id: input.projectId };
  return body;
}

export type VoucherPostingInput = {
  accountId: number;
  amountGross: number;
  amountGrossCurrency?: number;
  date: string;
  vatTypeId?: number;
  row?: number;
  description?: string;
  departmentId?: number;
  projectId?: number;
  customerId?: number;
  supplierId?: number;
};

export function transformVoucherPosting(p: VoucherPostingInput): Record<string, unknown> {
  const out: Record<string, unknown> = {
    account: { id: p.accountId },
    amountGross: p.amountGross,
    date: p.date,
  };
  // Tripletex 422s a posting whose amountGrossCurrency differs from amountGross in the
  // company currency — including when it is absent — so default it to the NOK amount.
  // Wrong for a foreign-currency account (the default would book the NOK figure as the
  // foreign amount); callers posting there must pass amountGrossCurrency — the tool's
  // schema says so. SkyeTec's tenants hold NOK accounts only (2026-09-25).
  out.amountGrossCurrency = p.amountGrossCurrency ?? p.amountGross;
  if (p.vatTypeId !== undefined) out.vatType = { id: p.vatTypeId };
  if (p.row !== undefined) out.row = p.row;
  if (p.description !== undefined) out.description = p.description;
  if (p.departmentId !== undefined) out.department = { id: p.departmentId };
  if (p.projectId !== undefined) out.project = { id: p.projectId };
  if (p.customerId !== undefined) out.customer = { id: p.customerId };
  if (p.supplierId !== undefined) out.supplier = { id: p.supplierId };
  return out;
}
