package internationalizedfield

import "testing"

func TestInternationalizedField_UnmarshalJSON(t *testing.T) {
	type fields struct {
		fieldName string
		internal  internal
	}
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &InternationalizedField{
				fieldName: tt.fields.fieldName,
				internal:  tt.fields.internal,
			}
			if err := i.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
