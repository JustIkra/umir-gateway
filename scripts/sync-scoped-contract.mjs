import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const [publicPath, outputPath] = process.argv.slice(2);
if (!publicPath || !outputPath) throw Error('Usage: node scripts/sync-scoped-contract.mjs PUBLIC OUTPUT');
const bytes = readFileSync(publicPath);
const api = JSON.parse(bytes);
if (api.info.version !== '2.0.0-REG.1' || !api['x-fin-source']?.['ui-amendment-v1-composed-public.json']) throw Error('Expected composed REG1 profile');
const bindings = {
  "supplySuggestions": {
    "path": "/api/v2/r/{restaurantID}/warehouse/supply-suggestions",
    "method": "GET",
    "capability": "stock.read",
    "owner": "warehouse"
  },
  "products": {
    "path": "/api/v2/r/{restaurantID}/warehouse/products",
    "method": "GET",
    "capability": "catalog.read",
    "owner": "warehouse"
  },
  "registerProduct": {
    "path": "/api/v2/r/{restaurantID}/warehouse/products",
    "method": "POST",
    "capability": "catalog.write",
    "owner": "warehouse"
  },
  "dishCatalog": {
    "path": "/api/v2/r/{restaurantID}/warehouse/dish-catalog",
    "method": "GET",
    "capability": "catalog.read",
    "owner": "warehouse"
  },
  "dishDetails": {
    "path": "/api/v2/r/{restaurantID}/warehouse/dish",
    "method": "GET",
    "capability": "catalog.read",
    "owner": "warehouse"
  },
  "defineDish": {
    "path": "/api/v2/r/{restaurantID}/warehouse/dishes",
    "method": "POST",
    "capability": "catalog.write",
    "owner": "warehouse"
  },
  "receiveDelivery": {
    "path": "/api/v2/r/{restaurantID}/warehouse/deliveries",
    "method": "POST",
    "capability": "delivery.create",
    "owner": "warehouse"
  },
  "inventory": {
    "path": "/api/v2/r/{restaurantID}/warehouse/inventory",
    "method": "GET",
    "capability": "stock.read",
    "owner": "warehouse"
  },
  "expiringBatches": {
    "path": "/api/v2/r/{restaurantID}/warehouse/expiring-batches",
    "method": "GET",
    "capability": "stock.read",
    "owner": "warehouse"
  },
  "history": {
    "path": "/api/v2/r/{restaurantID}/warehouse/history",
    "method": "GET",
    "capability": "stock.read",
    "owner": "warehouse"
  },
  "confirmWriteoff": {
    "path": "/api/v2/r/{restaurantID}/warehouse/writeoffs",
    "method": "POST",
    "capability": "writeoff.confirm",
    "owner": "warehouse"
  },
  "suggestID": {
    "path": "/api/v2/r/{restaurantID}/warehouse/id-suggestions",
    "method": "GET",
    "capability": "catalog.write",
    "owner": "warehouse"
  },
  "servingProducts": {
    "path": "/api/v2/r/{restaurantID}/serving/products",
    "method": "GET",
    "capability": "menu.read",
    "owner": "serving"
  },
  "servingDishes": {
    "path": "/api/v2/r/{restaurantID}/serving/dish-catalog",
    "method": "GET",
    "capability": "menu.read",
    "owner": "serving"
  },
  "servingDish": {
    "path": "/api/v2/r/{restaurantID}/serving/dish",
    "method": "GET",
    "capability": "menu.read",
    "owner": "serving"
  },
  "menu": {
    "path": "/api/v2/r/{restaurantID}/serving/menu",
    "method": "GET",
    "capability": "menu.read",
    "owner": "serving"
  },
  "stopList": {
    "path": "/api/v2/r/{restaurantID}/serving/stop-list",
    "method": "GET",
    "capability": "menu.read",
    "owner": "serving"
  },
  "recommendations": {
    "path": "/api/v2/r/{restaurantID}/serving/recommendations",
    "method": "GET",
    "capability": "recommendations.read",
    "owner": "serving"
  },
  "prepareOrder": {
    "path": "/api/v2/r/{restaurantID}/serving/order-proposals",
    "method": "POST",
    "capability": "order.prepare",
    "owner": "serving"
  },
  "confirmOrder": {
    "path": "/api/v2/r/{restaurantID}/serving/order-confirmations",
    "method": "POST",
    "capability": "order.confirm",
    "owner": "serving"
  },
  "resolveOrder": {
    "path": "/api/v2/r/{restaurantID}/serving/order-confirmations/resolve",
    "method": "GET",
    "capability": "order.read",
    "owner": "serving"
  },
  "analyticsstock": {
    "path": "/api/v2/r/{restaurantID}/warehouse/analytics/stock",
    "method": "GET",
    "capability": "analytics.read",
    "owner": "warehouse"
  },
  "analyticsmovements": {
    "path": "/api/v2/r/{restaurantID}/warehouse/analytics/movements",
    "method": "GET",
    "capability": "analytics.read",
    "owner": "warehouse"
  },
  "orgSummary": {
    "path": "/api/v2/orgs/{orgID}/analytics/summary",
    "method": "GET",
    "capability": "org.summary.read",
    "owner": "gateway"
  },
  "appFeedback": {
    "path": "/api/v2/r/{restaurantID}/feedback",
    "method": "POST",
    "capability": "feedback.submit",
    "owner": "feedback",
    "response": {
      "$ref": "#/components/schemas/FeedbackSaved"
    }
  },
  "anonymousFeedback": {
    "path": "/api/v2/feedback/anonymous",
    "method": "POST",
    "capability": "anonymous",
    "owner": "feedback",
    "response": {
      "$ref": "#/components/schemas/FeedbackSaved"
    }
  },
  "pendingWriteoffs": {
    "path": "/api/v2/r/{restaurantID}/warehouse/pending-writeoffs",
    "method": "GET",
    "capability": "stock.read",
    "owner": "warehouse"
  },
  "publicFeedbackRead": {
    "path": "/api/v2/r/{restaurantID}/feedback/submissions",
    "method": "GET",
    "capability": "feedback.read",
    "owner": "feedback"
  },
  "publicFeedbackExport": {
    "path": "/api/v2/r/{restaurantID}/feedback/export",
    "method": "GET",
    "capability": "feedback.export",
    "owner": "feedback"
  },
  "resolveWriteoffCommand": {
    "path": "/api/v2/r/{restaurantID}/warehouse/writeoffs/commands",
    "method": "GET",
    "capability": "writeoff.confirm",
    "owner": "warehouse"
  },
  "live": {
    "path": "/api/v2/r/{restaurantID}/live",
    "method": "GET",
    "capability": "restaurant-access",
    "owner": "Gateway",
    "response": {
      "$ref": "#/components/schemas/LiveEvent"
    }
  },
  "productBatches": {
    "path": "/api/v2/r/{restaurantID}/warehouse/products/{productID}/batches",
    "method": "GET",
    "capability": "stock.read",
    "owner": "warehouse"
  }
};
const operations = {};
const schemas = {};
function include(value) {
  if (!value || typeof value !== 'object') return;
  if (value.$ref) {
    const name = value.$ref.replace('#/components/schemas/', '');
    const schema = api.components.schemas[name];
    if (!schema) throw Error('Unknown schema ' + name);
    if (!(name in schemas)) { schemas[name] = schema; include(schema); }
  }
  for (const child of Object.values(value)) include(child);
}
for (const [id, binding] of Object.entries(bindings)) {
  const op = api.paths[binding.path]?.[binding.method.toLowerCase()];
  if (!op) throw Error('Missing public operation ' + id);
  const response = binding.response ?? op.responses['200']?.content?.['application/json']?.schema;
  const { response: ignored, ...metadata } = binding;
  operations[id] = { ...metadata,
    parameters: (op.parameters ?? []).map(p => p.$ref ? api.components.parameters[p.$ref.split('/').pop()] : p),
    ...(op.requestBody ? { request: op.requestBody.content['application/json'].schema } : {}),
    ...(response ? { response } : {}) };
  include(operations[id]);
}
for (const name of ["AccessCheckRequest","Allocation","AnonymousAuthorizationRequest","AuthorizationRequest","AuthorizationResult","BaseUnit","Batch","BatchExpiredEvent","BatchExpiryPendingEvent","BatchStatus","BatchV2","BatchWriteoffConfirmedEvent","BusinessContext","Capability","Change","CivilInput","ClientCommandID","CompleteMovementReport","CompleteStockReport","ConfirmOrderRequest","ConfirmResult","ConfirmationPending","Coverage","Date","Deficit","DefineDishRequest","Delivery","DeliveryLine","DeliveryLineV2","DeliveryReceiptV2","DeliveryReceivedEvent","DeliveryReceivedV2Event","Dish","DishCatalog","DishDefinedEvent","DishDetails","EmptyOrder","EntityID","Epoch","Error","ExpiringBatch","ExpiringBatches","ExpiryResult","FeedbackContext","FeedbackList","FeedbackReceipt","FeedbackSaved","FeedbackSubmission","Fingerprint","History","HistoryEvent","ID","Ingredient","IngredientInput","Instant","Inventory","JournalRecord","LocalDateTime","Menu","MenuDish","MovementReport","MovementRow","NonNegativeInt64","Order","OrderConfirmed","OrderPlacedEvent","OrderProposal","OrgRole","OrgSummary","Outcome","PageIdentity","PendingBatches","Position","PositiveInt64","PositiveQuantity","PrepareOrderRequest","Product","ProductRegisteredEvent","Products","ProposalSuperseded","Quantity","ReceiveDeliveryV2","Recommendation","RecommendationReason","Recommendations","RecordedDish","RecordedIngredient","RegisterProductRequest","RequestedPosition","RequiresConfirmation","RestaurantAccess","Role","ScopedDeliveryReceipt","ScopedDish","ScopedDishCatalog","ScopedDishDetails","ScopedExpiringBatches","ScopedFeedback","ScopedHistory","ScopedInventory","ScopedProduct","ScopedProducts","ScopedSuggestion","ScopedWriteoffResult","ServingContext","ServingScopedConfirmResult","ServingScopedDishCatalog","ServingScopedDishDetails","ServingScopedMenu","ServingScopedOrderProposal","ServingScopedProducts","ServingScopedRecommendations","ServingScopedStopList","Session","Settings","ShelfLife","StockReport","StockRow","StopList","StopListDish","Suggestion","SummaryItem","TimeInput","TimeZone","Token","Version","WriteoffCommandLookup","WriteoffRequest","WriteoffResult","LiveEvent","Registry","RegistryEntry","Restaurant","RuntimeReadiness","RuntimeStatus","ServiceAuthorizationRequest","ServiceClaims","RegisterRuntime","CloseRuntime","ScopedDueExpiryResult","DueExpiryResult","DueExpiryRequest","JWKS","JWTPublicKey","ScopedProductBatches","ProductBatchPage","ProductBatchRow","PositiveBatch"]) include({$ref:'#/components/schemas/'+name});
writeFileSync(outputPath, JSON.stringify({
  contractIdentity: 'REG1:sha256:' + createHash('sha256').update(bytes).digest('hex'),
  operations,
  components: { schemas: Object.fromEntries(Object.entries(schemas).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) },
  predecessorContractIdentity: 'UA1:sha256:' + api['x-fin-source']['ui-amendment-v1-composed-public.json'],
  originalContractIdentity: 'sha256:733e102ff0b4f52bb49d435716f9f1720642c8fad3a8a5d0685847071950e9e6',
}, null, 2) + '\n');
