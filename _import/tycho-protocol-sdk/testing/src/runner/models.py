from pydantic import BaseModel, Field
from typing import List, Dict, Optional

from tycho_client.dto import ProtocolComponent


class ProtocolComponentExpectation(BaseModel):
    """Represents a ProtocolComponent with its main attributes."""

    id: str = Field(..., description="Identifier of the protocol component")
    tokens: List[str] = Field(
        ...,
        description="List of token addresses associated with the protocol component",
    )
    static_attributes: Optional[Dict[str, Optional[str]]] = Field(
        default_factory=dict, description="Static attributes of the protocol component"
    )
    creation_tx: str = Field(
        ..., description="Hash of the transaction that created the protocol component"
    )

    def __init__(self, **data):
        super().__init__(**data)
        self.id = self.id.lower()
        self.tokens = sorted([t.lower() for t in self.tokens])

    def compare(self, other: "ProtocolComponentExpectation") -> Optional[str]:
        """Compares the current instance with another ProtocolComponent instance and returns a message with the differences or None if there are no differences."""
        differences = []
        for field_name, field_value in self.__dict__.items():
            other_value = getattr(other, field_name, None)
            if field_value != other_value:
                differences.append(
                    f"Field '{field_name}' mismatch: '{field_value}' != '{other_value}'"
                )
        if not differences:
            return None

        return "\n".join(differences)

    @staticmethod
    def from_dto(dto: ProtocolComponent) -> "ProtocolComponentExpectation":
        return ProtocolComponentExpectation(
            id=dto.id,
            tokens=[t.hex() for t in dto.tokens],
            static_attributes={
                key: value.hex() for key, value in dto.static_attributes.items()
            },
            creation_tx=dto.creation_tx.hex(),
        )


class ProtocolComponentWithTestConfig(ProtocolComponentExpectation):
    """Represents a ProtocolComponent with its main attributes and test configuration."""

    skip_simulation: Optional[bool] = Field(
        False,
        description="Flag indicating whether to skip simulation for this component",
    )

    def into_protocol_component(self) -> ProtocolComponentExpectation:
        return ProtocolComponentExpectation(**self.dict())


class IntegrationTest(BaseModel):
    """Configuration for an individual test."""

    name: str = Field(..., description="Name of the test")
    start_block: int = Field(..., description="Starting block number for the test")
    stop_block: int = Field(..., description="Stopping block number for the test")
    initialized_accounts: Optional[List[str]] = Field(
        None, description="List of initialized account addresses"
    )
    expected_components: List[ProtocolComponentWithTestConfig] = Field(
        ..., description="List of protocol components expected in the indexed state"
    )


class IntegrationTestsConfig(BaseModel):
    """Main integration test configuration."""

    substreams_yaml_path: str = Field(
        "./substreams.yaml", description="Path of the Substreams YAML file"
    )
    adapter_contract: str = Field(
        ..., description="Name of the SwapAdapter contract for this protocol"
    )
    adapter_build_signature: Optional[str] = Field(
        None, description="Signatre of the SwapAdapter constructor for this protocol"
    )
    adapter_build_args: Optional[str] = Field(
        None, description="Arguments for the SwapAdapter constructor for this protocol"
    )
    initialized_accounts: Optional[List[str]] = Field(
        None,
        description="List of initialized account addresses. These accounts will be initialized for every tests",
    )
    skip_balance_check: bool = Field(
        ..., description="Flag to skip balance check for all tests"
    )
    protocol_type_names: List[str] = Field(
        ..., description="List of protocol type names for the tested protocol"
    )
    tests: List[IntegrationTest] = Field(..., description="List of integration tests")
